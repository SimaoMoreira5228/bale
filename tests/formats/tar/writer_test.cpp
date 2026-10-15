#include "formats/tar/writer.hpp"

#include "checksum/crc.hpp"
#include "formats/compressed/output.hpp"
#include "formats/compressed/stream.hpp"
#include "formats/tar/reader.hpp"
#include "formats/tar/source.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <string>
#include <utility>
#include <vector>

using namespace bale;
using namespace bale::tar;

namespace {

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

std::vector<std::byte> readAll(const std::filesystem::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto size = file->size();
    REQUIRE(size);
    std::vector<std::byte> data(static_cast<std::size_t>(*size));
    REQUIRE(file->readExactAt(0, data));
    return data;
}

Writer createWriter(const std::filesystem::path& path, Compression compression) {
    auto file = File::createNew(path);
    REQUIRE(file);
    auto output = CompressedOutput::create(std::move(*file), compression);
    REQUIRE(output);
    return Writer(std::move(*output));
}

struct Decoded {
    HeaderBuffers buffers;
    Header header;
    PaxValues pax;
    std::size_t blocks = 0;
};

Decoded decode(const WriteEntry& entry) {
    Decoded decoded;
    HeaderBuffers& buffers = decoded.buffers;
    REQUIRE(encodeHeaders(entry, buffers));
    REQUIRE(buffers.blocks.size() % blockSize == 0);

    decoded.blocks = buffers.blocks.size() / blockSize;
    auto last = std::span(buffers.blocks).last<blockSize>();
    auto header = parseHeader(last, 0);
    REQUIRE(header);
    decoded.header = *header;

    if (decoded.blocks > 1) {
        auto pax = parseHeader(std::span(buffers.blocks).first<blockSize>(), 0);
        REQUIRE(pax);
        CHECK(pax->typeflag == 'x');
        std::string_view records(
            reinterpret_cast<const char*>(buffers.blocks.data() + blockSize),
            static_cast<std::size_t>(pax->size)
        );
        REQUIRE(parsePaxRecords(records, 0, Limits{}, decoded.pax));
    }
    return decoded;
}

WriteEntry file(std::string_view path) {
    return WriteEntry{.path = path, .mode = 0644};
}

}

TEST_CASE("tar writer output matches Python's ustar bytes") {
    bale::test::TempPath temp;
    auto writer = createWriter(temp.path(), Compression::None);
    constexpr std::int64_t mtime = 1'700'000'000;

    REQUIRE(
        writer.add({.path = "d", .mtimeSeconds = mtime, .mode = 0755, .kind = EntryKind::Directory})
    );
    REQUIRE(writer.add({.path = "d/f.txt", .size = 6, .mtimeSeconds = mtime, .mode = 0644}));
    REQUIRE(writer.write(bytesOf("hello\n")));
    REQUIRE(writer.add(
        {.path = "d/l",
         .linkTarget = "f.txt",
         .mtimeSeconds = mtime,
         .mode = 0777,
         .kind = EntryKind::Symlink}
    ));
    REQUIRE(writer.add(
        {.path = "d/h",
         .linkTarget = "d/f.txt",
         .mtimeSeconds = mtime,
         .mode = 0644,
         .kind = EntryKind::HardLink}
    ));
    REQUIRE(writer.finish() == recordSize);

    // NOTE: golden CRC-32 of Python 3 tarfile USTAR_FORMAT output for the same four entries
    // with empty uname and gname.
    auto written = readAll(temp.path());
    CHECK(written.size() == recordSize);
    CHECK(Crc32::of(written) == 0x6cd4468a);
}

TEST_CASE("tar writer adds pax records exactly at the ustar limits") {
    std::string name100(100, 'n');
    std::string name101(101, 'n');
    auto decoded = decode(file(name100));
    CHECK(decoded.blocks == 1);
    CHECK(decoded.header.name == name100);
    decoded = decode(file(name101));
    CHECK(decoded.blocks > 1);
    CHECK(decoded.pax.path == name101);

    std::string prefix155(155, 'p');
    std::string split = prefix155 + "/" + name100;
    decoded = decode(file(split));
    CHECK(decoded.blocks == 1);
    CHECK(decoded.header.prefix == prefix155);
    CHECK(decoded.header.name == name100);
    std::string tooLong = std::string(156, 'p') + "/" + name100;
    decoded = decode(file(tooLong));
    CHECK(decoded.pax.path == tooLong);

    decoded = decode(file("caf\xC3\xA9.txt"));
    CHECK(decoded.pax.path == "caf\xC3\xA9.txt");

    WriteEntry link = file("l");
    link.kind = EntryKind::Symlink;
    link.linkTarget = name100;
    CHECK(decode(link).blocks == 1);
    link.linkTarget = name101;
    CHECK(decode(link).pax.linkPath == name101);

    WriteEntry big = file("big");
    big.size = 077777777777;
    decoded = decode(big);
    CHECK(decoded.blocks == 1);
    CHECK(decoded.header.size == big.size);
    big.size += 1;
    decoded = decode(big);
    CHECK(decoded.pax.hasSize);
    CHECK(decoded.pax.size == big.size);

    WriteEntry owner = file("owner");
    owner.uid = 07777777;
    owner.gid = 07777777 + 1;
    decoded = decode(owner);
    CHECK_FALSE(decoded.pax.hasUid);
    CHECK(decoded.pax.gid == owner.gid);

    WriteEntry timed = file("timed");
    timed.mtimeSeconds = 5;
    CHECK(decode(timed).blocks == 1);
    timed.mtimeNanoseconds = 1;
    decoded = decode(timed);
    CHECK(decoded.pax.mtimeSeconds == 5);
    CHECK(decoded.pax.mtimeNanoseconds == 1);
    timed.mtimeSeconds = -2;
    timed.mtimeNanoseconds = 250'000'000;
    decoded = decode(timed);
    CHECK(decoded.pax.mtimeSeconds == -2);
    CHECK(decoded.pax.mtimeNanoseconds == 250'000'000);
}

TEST_CASE("tar writer refuses malformed entries and size mismatches") {
    HeaderBuffers buffers;
    CHECK_FALSE(encodeHeaders(file(""), buffers));
    CHECK_FALSE(encodeHeaders(WriteEntry{.path = "x", .kind = EntryKind::Symlink}, buffers));
    CHECK_FALSE(encodeHeaders(WriteEntry{.path = "x", .kind = EntryKind::Fifo}, buffers));
    CHECK_FALSE(
        encodeHeaders(WriteEntry{.path = "x", .size = 1, .kind = EntryKind::Directory}, buffers)
    );

    bale::test::TempPath temp;
    auto writer = createWriter(temp.path(), Compression::None);
    REQUIRE(writer.add({.path = "short", .size = 4}));
    CHECK_FALSE(writer.write(bytesOf("toolong")));
    CHECK_FALSE(writer.finish());
}

TEST_CASE("tar writer streams through gzip and zstd and reads back") {
    std::string content(200'000, 'z');
    for (std::size_t index = 0; index < content.size(); index += 7) {
        content[index] = static_cast<char>('a' + index % 26);
    }
    std::string longName =
        std::string(120, 'd') + "/\xE6\x9D\xB1\xE4\xBA\xAC-" + std::string(110, 'f');

    for (auto compression : {Compression::None, Compression::Gzip, Compression::Zstd}) {
        bale::test::TempPath temp;
        auto writer = createWriter(temp.path(), compression);
        REQUIRE(writer.add({.path = "empty", .kind = EntryKind::Directory}));
        REQUIRE(writer.add({.path = longName, .size = content.size(), .mtimeNanoseconds = 7}));
        REQUIRE(writer.write(bytesOf(content).first(1000)));
        REQUIRE(writer.write(bytesOf(content).subspan(1000)));
        REQUIRE(writer.add({.path = "zero"}));
        REQUIRE(writer.finish());

        auto archive = File::openRead(temp.path());
        REQUIRE(archive);
        Result<Source> source = compression == Compression::None ? Source::open(std::move(*archive))
                                                                 : [&]() -> Result<Source> {
            auto stream = CompressedStream::open(std::move(*archive), compression);
            REQUIRE(stream);
            return Source(std::move(*stream));
        }();
        REQUIRE(source);

        Reader reader(std::move(*source));
        auto directory = reader.next();
        REQUIRE(directory);
        REQUIRE(*directory != nullptr);
        CHECK((*directory)->kind == EntryKind::Directory);
        CHECK((*directory)->path == "empty/");

        auto entry = reader.next();
        REQUIRE(entry);
        REQUIRE(*entry != nullptr);
        CHECK((*entry)->path == longName);
        CHECK((*entry)->mtimeNanoseconds == 7);

        std::string read;
        std::vector<std::byte> scratch(4096);
        REQUIRE(reader.streamData(scratch, [&read](std::span<const std::byte> chunk) {
            read.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        }));
        CHECK(read == content);

        auto zero = reader.next();
        REQUIRE(zero);
        REQUIRE(*zero != nullptr);
        CHECK((*zero)->size == 0);
        auto end = reader.next();
        REQUIRE(end);
        CHECK(*end == nullptr);
    }
}
