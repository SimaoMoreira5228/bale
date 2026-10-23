#include "formats/tar/reader.hpp"

#include "codecs/codec_fixture.hpp"
#include "formats/compressed/stream.hpp"
#include "formats/tar/tar_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <string>
#include <utility>
#include <vector>

using namespace bale;
using namespace bale::tar;
using namespace bale::tar::test;

namespace {

using Bytes = std::vector<std::byte>;

HeaderSpec named(std::string name, char typeflag = '0') {
    HeaderSpec spec;
    spec.name = std::move(name);
    spec.typeflag = typeflag;
    return spec;
}

std::string patterned(std::size_t size) {
    std::string text(size, '-');
    for (std::size_t index = 0; index < text.size(); index += 41) {
        text[index] = static_cast<char>('a' + index % 26);
    }
    return text;
}

std::string bigContent() {
    return patterned(300'000);
}

std::string longPath() {
    return "pax/" + std::string(150, 'p');
}

Bytes sampleTar() {
    ArchiveBuilder builder;
    builder.meta('x', paxRecord("path", longPath())).entry(named("short"), "pax entry");
    builder.entry(named("big.bin"), bigContent()).entry(named("dir/", '5'), "");
    builder.entry(named("small.txt"), "hello").zeros(2).raw(10 * blockSize, std::byte{0});
    return builder.bytes();
}

Bytes compress(const Bytes& data, Compression compression) {
    if (compression == Compression::Gzip) {
        return bale::test::gzipMember(data);
    }
    if (compression == Compression::Zstd) {
        return bale::test::zstdCompress(data, 20);
    }
    if (compression == Compression::Xz) {
        return bale::test::xzCompress(data);
    }
    return bale::test::bzip2Compress(data);
}

Bytes slice(const Bytes& bytes, std::size_t begin, std::size_t end) {
    return {
        bytes.begin() + static_cast<std::ptrdiff_t>(begin),
        bytes.begin() + static_cast<std::ptrdiff_t>(end)
    };
}

Source openSource(
    const bale::test::TempFile& temp,
    Compression compression,
    const DecompressLimits& limits = {}
) {
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    auto stream = CompressedStream::open(std::move(*file), compression, limits);
    REQUIRE(stream);
    return Source(std::move(*stream));
}

struct Archive {
    Archive(
        std::span<const std::byte> bytes,
        Compression compression,
        const DecompressLimits& limits = {}
    ) : file(bytes), reader(openSource(file, compression, limits)) {
    }

    bale::test::TempFile file;
    Reader reader;
};

Result<std::string> readData(Reader& reader, std::size_t scratchSize = 4096) {
    std::string data;
    std::vector<std::byte> scratch(scratchSize);
    auto streamed = reader.streamData(scratch, [&data](std::span<const std::byte> chunk) {
        data.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    if (!streamed) {
        return tl::unexpected<Error>(streamed.error());
    }
    return data;
}

const Entry& nextEntry(Reader& reader) {
    auto next = reader.next();
    REQUIRE(next);
    REQUIRE(*next != nullptr);
    return **next;
}

void readAllEntries(Reader& reader) {
    CHECK(nextEntry(reader).path == longPath());
    CHECK(readData(reader) == "pax entry");
    CHECK(nextEntry(reader).path == "big.bin");
    CHECK(readData(reader, 1000) == bigContent());
    CHECK(nextEntry(reader).kind == EntryKind::Directory);
    CHECK(nextEntry(reader).path == "small.txt");
    CHECK(readData(reader) == "hello");
}

ErrorKind finalError(Reader& reader) {
    auto end = reader.next();
    REQUIRE_FALSE(end);
    return end.error().kind;
}

}

TEST_CASE("Compressed tar round trips through every compressed stream") {
    auto tar = sampleTar();
    for (auto compression :
         {Compression::Gzip, Compression::Zstd, Compression::Xz, Compression::Bzip2}) {
        for (std::size_t chunk : {std::size_t{700}, std::size_t{64} << 10}) {
            CAPTURE(compression);
            CAPTURE(chunk);
            Archive archive(compress(tar, compression), compression, {.chunkBytes = chunk});

            readAllEntries(archive.reader);
            CHECK(archive.reader.next() == nullptr);
            CHECK(archive.reader.next() == nullptr);
        }
    }
}

TEST_CASE("Multi-member gzip carries one tar split inside headers and data") {
    auto tar = sampleTar();
    auto bytes = bale::test::gzipMember(slice(tar, 0, 700));
    for (auto [begin, end] :
         {std::pair{std::size_t{700}, std::size_t{1024}},
          std::pair{std::size_t{1024}, std::size_t{200'000}},
          std::pair{std::size_t{200'000}, tar.size()}}) {
        auto member = bale::test::gzipMember(slice(tar, begin, end));
        bytes.insert(bytes.end(), member.begin(), member.end());
    }

    Archive archive(bytes, Compression::Gzip);
    readAllEntries(archive.reader);
    CHECK(archive.reader.next() == nullptr);
}

TEST_CASE("Sequential reader skips unread and partly read entry data") {
    Archive archive(compress(sampleTar(), Compression::Zstd), Compression::Zstd);
    auto& reader = archive.reader;

    CHECK(nextEntry(reader).path == longPath());

    CHECK(nextEntry(reader).path == "big.bin");
    std::vector<std::byte> scratch(1000);
    std::size_t delivered = 0;
    auto stopped = reader.streamData(scratch, [&delivered](std::span<const std::byte> chunk) {
        delivered += chunk.size();
        return Result<void>(fail(ErrorKind::Io, "sink refused"));
    });
    REQUIRE_FALSE(stopped);
    CHECK(stopped.error().what == "sink refused");
    CHECK(delivered == 1000);

    CHECK(nextEntry(reader).kind == EntryKind::Directory);
    const auto& small = nextEntry(reader);
    CHECK(small.path == "small.txt");
    CHECK(small.dataOffset == 7 * blockSize + 300'032);
    CHECK(readData(reader) == "hello");
    CHECK(readData(reader) == "");
    CHECK(reader.next() == nullptr);
}

TEST_CASE("Compressed tar truncated mid-entry is reported as truncated") {
    auto tar = sampleTar();
    for (auto compression :
         {Compression::Gzip, Compression::Zstd, Compression::Xz, Compression::Bzip2}) {
        CAPTURE(compression);
        auto bytes = compress(slice(tar, 0, 10'000), compression);
        auto rest = compress(slice(tar, 10'000, tar.size()), compression);
        auto cut = slice(rest, 0, rest.size() / 2);
        bytes.insert(bytes.end(), cut.begin(), cut.end());
        Archive archive(bytes, compression);
        auto& reader = archive.reader;

        CHECK(nextEntry(reader).path == longPath());
        CHECK(nextEntry(reader).path == "big.bin");
        auto data = readData(reader);
        REQUIRE_FALSE(data);
        CHECK(data.error().kind == ErrorKind::Truncated);
        CHECK(finalError(reader) == ErrorKind::Truncated);
    }

    Archive cutTar(bale::test::gzipMember(slice(tar, 0, 3 * blockSize + 5000)), Compression::Gzip);
    CHECK(nextEntry(cutTar.reader).path == longPath());
    CHECK(nextEntry(cutTar.reader).path == "big.bin");
    auto cut = cutTar.reader.next();
    REQUIRE_FALSE(cut);
    CHECK(cut.error().what == "tar archive ends inside entry data");
}

TEST_CASE("Codec checksum failures surface after all tar data was read") {
    auto tar = sampleTar();

    auto gzipBytes = compress(tar, Compression::Gzip);
    gzipBytes[gzipBytes.size() - 8] ^= std::byte{0x40};
    Archive gzipArchive(gzipBytes, Compression::Gzip);
    readAllEntries(gzipArchive.reader);
    CHECK(finalError(gzipArchive.reader) == ErrorKind::Integrity);

    auto zstdBytes = compress(tar, Compression::Zstd);
    zstdBytes.back() ^= std::byte{0x40};
    Archive zstdArchive(zstdBytes, Compression::Zstd);
    readAllEntries(zstdArchive.reader);
    CHECK(finalError(zstdArchive.reader) == ErrorKind::Integrity);

    auto trailing = compress(tar, Compression::Gzip);
    trailing.push_back(std::byte{'X'});
    Archive trailingArchive(trailing, Compression::Gzip);
    readAllEntries(trailingArchive.reader);
    CHECK(finalError(trailingArchive.reader) == ErrorKind::Malformed);
}

TEST_CASE("Compressed tar stops at the output budget whether data is read or skipped") {
    auto bytes = compress(sampleTar(), Compression::Gzip);

    Archive streamed(bytes, Compression::Gzip, {.maxOutputBytes = 100'000});
    CHECK(nextEntry(streamed.reader).path == longPath());
    CHECK(nextEntry(streamed.reader).path == "big.bin");
    auto data = readData(streamed.reader);
    REQUIRE_FALSE(data);
    CHECK(data.error().kind == ErrorKind::LimitExceeded);

    bale::test::TempFile skipped(bytes);
    auto listing = listSource(openSource(skipped, Compression::Gzip, {.maxOutputBytes = 100'000}));
    CHECK((listing.error && listing.error->kind == ErrorKind::LimitExceeded));
    CHECK(listing.entries.size() == 2);
}

TEST_CASE("Sequential reader detects a lying entry size only when it runs out of data") {
    auto lying = named("liar");
    lying.base256Size = true;
    lying.size = std::uint64_t{1} << 40;

    ArchiveBuilder builder;
    builder.block(makeHeader(lying)).data("tiny").zeros(2);
    auto seekable = listArchive(builder.bytes());
    CHECK((seekable.error && seekable.error->kind == ErrorKind::Truncated));

    Archive archive(bale::test::gzipMember(builder.bytes()), Compression::Gzip);
    CHECK(nextEntry(archive.reader).size == std::uint64_t{1} << 40);
    CHECK(finalError(archive.reader) == ErrorKind::Truncated);
}
