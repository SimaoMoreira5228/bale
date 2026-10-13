#include "archive/manifest.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"

#include "archive/archive_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::contents;
using bale::test::fixedOptions;
using bale::test::newWriter;
using bale::test::readAll;
using bale::test::TempPath;

namespace fs = std::filesystem;

namespace {

std::string noise(std::size_t length, std::uint32_t seed) {
    std::string out(length, '\0');
    std::uint32_t value = seed | 1;
    for (char& byte : out) {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        byte = static_cast<char>(value & 0xFF);
    }
    return out;
}

std::string text(std::size_t length, std::uint32_t seed) {
    std::string out;
    while (out.size() < length) {
        out += "line " + std::to_string(seed++ % 97) + " of a compressible file\n";
    }
    out.resize(length);
    return out;
}

void writeText(const fs::path& path, const std::string& data) {
    std::ofstream out(path, std::ios::binary);
    out << data;
}

void buildTree(const fs::path& root) {
    fs::create_directories(root / "small");
    fs::create_directories(root / "large");
    for (std::uint32_t index = 0; index < 64; ++index) {
        writeText(
            root / "small" / ("f" + std::to_string(index)),
            text(std::size_t{index} * 37, index)
        );
    }
    std::string shared = noise(std::size_t{5} * minChunkSize, 7);
    for (std::uint32_t index = 0; index < 6; ++index) {
        std::string data = index % 2 == 0 ? text(std::size_t{9} * minChunkSize + index, index)
                                          : noise(std::size_t{7} * minChunkSize + index, index);
        writeText(root / "large" / ("g" + std::to_string(index)), data + shared);
    }
}

std::vector<std::byte> canonicalManifest(const Reader& reader) {
    Manifest manifest = reader.manifest();
    manifest.writer.workers = 1;
    std::vector<std::byte> out;
    REQUIRE(encodeManifest(manifest, out));
    return out;
}

std::span<const std::byte> recordBytes(std::span<const std::byte> archive, RecordReference record) {
    return archive.subspan(
        static_cast<std::size_t>(record.offset),
        static_cast<std::size_t>(record.length)
    );
}

Reader openArchive(const fs::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    return std::move(*reader);
}

// NOTE: the recorded worker count is the only input that may differ: every DATA record, the index
// and the manifest apart from that field must be byte-identical to the one-worker archive.
void requireSameArchive(const fs::path& single, const fs::path& parallel, std::uint32_t workers) {
    auto singleBytes = readAll(single);
    auto parallelBytes = readAll(parallel);
    Reader singleReader = openArchive(single);
    Reader parallelReader = openArchive(parallel);

    CHECK(singleReader.manifest().writer.workers == 1);
    CHECK(parallelReader.manifest().writer.workers == workers);
    REQUIRE(singleBytes.size() == parallelBytes.size());

    const Commit& commit = singleReader.commit();
    CHECK(parallelReader.commit().manifest.offset == commit.manifest.offset);
    CHECK(parallelReader.commit().index.offset == commit.index.offset);
    auto dataEnd = static_cast<std::size_t>(commit.manifest.offset);
    CHECK(
        std::ranges::equal(
            std::span(singleBytes).first(dataEnd),
            std::span(parallelBytes).first(dataEnd)
        )
    );
    CHECK(
        std::ranges::equal(
            recordBytes(singleBytes, commit.index),
            recordBytes(parallelBytes, parallelReader.commit().index)
        )
    );
    CHECK(canonicalManifest(singleReader) == canonicalManifest(parallelReader));
    CHECK(parallelReader.verify(VerifyMode::Content));
}

WriterOptions zstdOptions(std::uint32_t workers, CodecId codec = CodecId::Zstd) {
    WriterOptions options = fixedOptions(minChunkSize);
    options.compression = CompressionProfile{
        .preset = std::nullopt,
        .codec = codec,
        .level = codec == CodecId::Zstd ? 1 : 0,
    };
    options.workers = workers;
    return options;
}

}

TEST_CASE("parallel workers write the same records as one worker") {
    TempPath temp;
    fs::path root = temp.path() / "tree";
    buildTree(root);

    for (CodecId codec : {CodecId::Zstd, CodecId::Lz4, CodecId::Raw}) {
        CAPTURE(static_cast<int>(codec));
        std::string prefix = std::to_string(static_cast<int>(codec)) + "-";
        auto options = [codec](std::uint32_t workers) {
            return zstdOptions(workers, codec);
        };

        fs::path single = temp.path() / (prefix + "1.bale");
        auto writer = newWriter(single, options(1));
        REQUIRE(writer.addTree(root));
        auto expected = writer.finish();
        REQUIRE(expected);

        for (std::uint32_t workers : {2U, 3U, 8U}) {
            CAPTURE(workers);
            fs::path parallel = temp.path() / (prefix + std::to_string(workers) + ".bale");
            auto parallelWriter = newWriter(parallel, options(workers));
            REQUIRE(parallelWriter.addTree(root));
            auto summary = parallelWriter.finish();
            REQUIRE(summary);
            CHECK(summary->dataRecords == expected->dataRecords);
            CHECK(summary->chunkReferences == expected->chunkReferences);
            requireSameArchive(single, parallel, workers);
        }
    }
}

TEST_CASE("duplicates inside the in-flight window are stored once, in input order") {
    TempPath temp;
    fs::create_directories(temp.path());
    std::vector<std::string> blocks;
    blocks.reserve(5);
    for (std::uint32_t index = 0; index < 5; ++index) {
        blocks.push_back(text(minChunkSize, index * 1000));
    }
    std::string data;
    std::string order = "0102310423014410";
    for (char block : order) {
        data += blocks[static_cast<std::size_t>(block - '0')];
    }
    data += "tail";

    std::vector<fs::path> paths;
    for (std::uint32_t workers : {1U, 4U}) {
        fs::path path = temp.path() / ("dup" + std::to_string(workers) + ".bale");
        auto writer = newWriter(path, zstdOptions(workers));
        REQUIRE(writer.addBytes("a", bytesOf(data)));
        REQUIRE(writer.addBytes("b", bytesOf(blocks[3] + blocks[0])));
        auto summary = writer.finish();
        REQUIRE(summary);
        CHECK(summary->dataRecords == 6);
        CHECK(summary->chunkReferences == order.size() + 1 + 2);
        paths.push_back(path);
    }
    requireSameArchive(paths[0], paths[1], 4);

    Reader reader = openArchive(paths[1]);
    const ManifestEntry* entry = findEntry(reader.manifest().entries, "a");
    REQUIRE(entry != nullptr);
    CHECK(contents(reader, *entry) == data);

    std::vector<std::uint64_t> offsets;
    for (const IndexEntry& indexed : reader.index()) {
        offsets.push_back(indexed.recordOffset);
    }
    std::ranges::sort(offsets);
    auto firstChunk =
        std::ranges::find(reader.index(), reader.manifest().chunks[0], &IndexEntry::key);
    REQUIRE(firstChunk != reader.index().end());
    CHECK(firstChunk->recordOffset == offsets.front());
}

TEST_CASE("a failure while chunks are in flight is returned and the workers stop") {
    TempPath temp;
    fs::path root = temp.path() / "tree";
    buildTree(root);

    SUBCASE("entry limit reached mid-tree") {
        WriterOptions options = zstdOptions(4);
        options.limits.maxEntries = 20;
        auto writer = newWriter(temp.path() / "limit.bale", options);
        auto added = writer.addTree(root);
        REQUIRE_FALSE(added);
        CHECK(added.error().kind == ErrorKind::LimitExceeded);
    }

#ifndef _WIN32
    SUBCASE("unreadable input after queued chunks") {
        auto writer = newWriter(temp.path() / "unreadable.bale", zstdOptions(4));
        std::string large = noise(std::size_t{40} * minChunkSize, 3);
        REQUIRE(writer.addBytes("large", bytesOf(large)));

        auto directory = File::openRead(root);
        REQUIRE(directory);
        auto added = writer.addFile("directory", *directory);
        REQUIRE_FALSE(added);
        CHECK(added.error().kind == ErrorKind::Io);

        auto finished = writer.finish();
        REQUIRE_FALSE(finished);
        CHECK(finished.error().kind == ErrorKind::Io);
        CHECK_FALSE(writer.addBytes("after", bytesOf("x")));
    }
#endif

    SUBCASE("abandoned writer with chunks in flight") {
        auto writer = newWriter(temp.path() / "abandoned.bale", zstdOptions(8));
        std::string large = text(std::size_t{64} * minChunkSize, 11);
        REQUIRE(writer.addBytes("large", bytesOf(large)));
    }
}

TEST_CASE("worker count outside 1-64 is refused") {
    TempPath temp;
    fs::create_directories(temp.path());
    for (std::uint32_t workers : {0U, maxWorkers + 1}) {
        auto file = File::createNew(temp.path() / ("bad" + std::to_string(workers)));
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), zstdOptions(workers));
        REQUIRE_FALSE(writer);
        CHECK(writer.error().kind == ErrorKind::LimitExceeded);
    }
    CHECK(defaultWorkers() >= 1);
    CHECK(defaultWorkers() <= 8);
}
