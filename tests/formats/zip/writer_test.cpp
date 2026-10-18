#include "formats/zip/writer.hpp"

#include "checksum/crc.hpp"
#include "formats/zip/reader.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <string>
#include <utility>
#include <vector>

using namespace bale;
using namespace bale::zip;

namespace {

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

Writer createWriter(const std::filesystem::path& path, const WriterOptions& options = {}) {
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = Writer::create(std::move(*file), options);
    REQUIRE(writer);
    return std::move(*writer);
}

Reader openReader(const std::filesystem::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    return std::move(*reader);
}

std::vector<Entry> entriesOf(const Reader& reader) {
    std::vector<Entry> entries;
    auto cursor = reader.entries();
    Entry entry;
    while (true) {
        auto more = cursor.next(entry);
        REQUIRE(more);
        if (!*more) {
            return entries;
        }
        entries.push_back(entry);
    }
}

std::string contentsOf(Reader& reader, const Entry& entry) {
    std::string out;
    std::vector<std::byte> scratch(8192);
    REQUIRE(reader.streamEntry(entry, scratch, [&out](std::span<const std::byte> chunk) {
        out.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    }));
    return out;
}

std::string randomText(std::size_t size) {
    std::uint64_t state = 0x9E3779B97F4A7C15;
    std::string text(size, '\0');
    for (auto& value : text) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        value = static_cast<char>(state >> 56);
    }
    return text;
}

std::size_t centralExtraLength(const CentralRecord& record) {
    std::vector<std::byte> out;
    appendCentralHeader(record, out);
    return static_cast<std::size_t>(out[30]) | (static_cast<std::size_t>(out[31]) << 8);
}

std::size_t endRecordsSize(std::uint64_t entries, std::uint64_t offset, std::uint64_t size) {
    std::vector<std::byte> out;
    appendEndRecords(entries, offset, size, out);
    return out.size();
}

}

TEST_CASE("ZIP writer output matches Python's stored archive bytes") {
    bale::test::TempPath temp;
    auto writer = createWriter(temp.path(), {.level = 0});
    constexpr std::int64_t mtime = 1'700'000'000;

    REQUIRE(
        writer.add({.path = "d", .mtimeSeconds = mtime, .mode = 0755, .kind = WriteKind::Directory})
    );
    REQUIRE(writer.add({.path = "d/f.txt", .size = 6, .mtimeSeconds = mtime, .mode = 0644}));
    REQUIRE(writer.write(bytesOf("hello\n")));
    REQUIRE(writer.add(
        {.path = "d/l", .linkTarget = "f.txt", .mtimeSeconds = mtime, .kind = WriteKind::Symlink}
    ));
    auto size = writer.finish();
    REQUIRE(size);

    // NOTE: golden CRC-32 of Python 3 zipfile output for the same entries, written as ZipInfo
    // records with create_system 3, create_version 45 and the same 0x5455 extra field.
    auto file = File::openRead(temp.path());
    REQUIRE(file);
    std::vector<std::byte> written(static_cast<std::size_t>(*size));
    REQUIRE(file->readExactAt(0, written));
    CHECK(written.size() == 339);
    CHECK(Crc32::of(written) == 0xcb8da3c1);
}

TEST_CASE("ZIP64 extra fields and end records appear exactly at the 32 and 16 bit limits") {
    CentralRecord record{.name = "f"};
    CHECK(centralExtraLength(record) == 0);
    record.uncompressedSize = 0xFFFFFFFE;
    record.compressedSize = 0xFFFFFFFE;
    record.localHeaderOffset = 0xFFFFFFFE;
    CHECK(centralExtraLength(record) == 0);
    record.uncompressedSize = 0xFFFFFFFF;
    CHECK(centralExtraLength(record) == 12);
    record.compressedSize = 0x1'0000'0000;
    record.localHeaderOffset = 0xFFFFFFFF;
    CHECK(centralExtraLength(record) == 28);
    record.mtimeSeconds = 0;
    CHECK(centralExtraLength(record) == 37);

    constexpr std::size_t classic = 22;
    constexpr std::size_t zip64 = classic + 56 + 20;
    CHECK(endRecordsSize(0xFFFE, 0xFFFFFFFE, 0xFFFFFFFE) == classic);
    CHECK(endRecordsSize(0xFFFF, 0, 0) == zip64);
    CHECK(endRecordsSize(0, 0xFFFFFFFF, 0) == zip64);
    CHECK(endRecordsSize(0, 0, 0xFFFFFFFF) == zip64);
}

TEST_CASE("ZIP writer switches to ZIP64 end records at 65535 entries and reads back") {
    for (std::uint64_t count : {std::uint64_t{0xFFFE}, std::uint64_t{0xFFFF}}) {
        bale::test::TempPath temp;
        auto writer = createWriter(temp.path());
        std::string name;
        bool added = true;
        for (std::uint64_t index = 0; index < count && added; ++index) {
            name = std::to_string(index);
            added = writer.add({.path = name, .kind = WriteKind::Directory}).has_value();
        }
        REQUIRE(added);
        REQUIRE(writer.finish());

        auto reader = openReader(temp.path());
        CHECK(reader.entryCount() == count);
        CHECK(reader.zip64() == (count == 0xFFFF));
    }
}

TEST_CASE("ZIP writer stores entries that deflate does not shrink, buffered or probed") {
    auto random = randomText(20'000);
    std::string text;
    for (int line = 0; text.size() < 20'000; ++line) {
        text += "line " + std::to_string(line % 50) + " of a compressible text file\n";
    }
    std::string smallRandom = random.substr(0, 3000);
    std::string smallText = text.substr(0, 3000);

    bale::test::TempPath temp;
    auto writer = createWriter(temp.path(), {.bufferBytes = 4096});
    for (auto [name, content] : {
             std::pair{"small-random", std::string_view(smallRandom)},
             std::pair{"small-text", std::string_view(smallText)},
             std::pair{"large-random", std::string_view(random)},
             std::pair{"large-text", std::string_view(text)},
         }) {
        REQUIRE(writer.add({.path = name, .size = content.size()}));
        for (std::size_t at = 0; at < content.size(); at += 1500) {
            REQUIRE(writer.write(bytesOf(content.substr(at, 1500))));
        }
    }
    REQUIRE(writer.add({.path = "caf\xC3\xA9", .linkTarget = "x", .kind = WriteKind::Symlink}));
    REQUIRE(writer.finish());

    auto reader = openReader(temp.path());
    auto entries = entriesOf(reader);
    REQUIRE(entries.size() == 5);
    CHECK(entries[0].method == methodStored);
    CHECK(entries[1].method == methodDeflate);
    CHECK(entries[2].method == methodStored);
    CHECK(entries[3].method == methodDeflate);
    CHECK(entries[3].compressedSize < text.size() / 4);
    CHECK(contentsOf(reader, entries[0]) == smallRandom);
    CHECK(contentsOf(reader, entries[1]) == smallText);
    CHECK(contentsOf(reader, entries[2]) == random);
    CHECK(contentsOf(reader, entries[3]) == text);

    CHECK(entries[4].utf8Name());
    CHECK(entries[4].unixMode == 0120777);
    CHECK(contentsOf(reader, entries[4]) == "x");
    CHECK(entries[0].unixMode == 0100644);
}

TEST_CASE("ZIP writer refuses data that disagrees with the declared size") {
    bale::test::TempPath temp;
    auto writer = createWriter(temp.path(), {.bufferBytes = 64});
    REQUIRE(writer.add({.path = "f", .size = 100}));
    REQUIRE(writer.write(bytesOf(std::string(80, 'a'))));
    CHECK_FALSE(writer.write(bytesOf(std::string(30, 'a'))));
    CHECK_FALSE(writer.finish());

    bale::test::TempPath other;
    auto shorter = createWriter(other.path());
    REQUIRE(shorter.add({.path = "f", .size = 10}));
    REQUIRE(shorter.write(bytesOf("abc")));
    CHECK_FALSE(shorter.finish());

    bale::test::TempPath third;
    auto file = File::createNew(third.path());
    REQUIRE(file);
    CHECK_FALSE(Writer::create(std::move(*file), {.level = 10}));
}
