#include "archive/cdc.hpp"
#include "archive/chunk.hpp"
#include "archive/manifest.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"

#include "archive/archive_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::contents;
using bale::test::newWriter;
using bale::test::readAll;
using bale::test::TempPath;

namespace {

WriterOptions cdcOptions(std::uint32_t workers = 1) {
    WriterOptions options;
    options.chunkSize = defaultChunkSize;
    options.chunkPolicy = ChunkPolicy::Cdc;
    options.cdc = defaultCdcParams;
    options.compression = CompressionProfile{
        .preset = std::nullopt,
        .codec = CodecId::Raw,
        .level = 0,
    };
    std::array<std::byte, 16> id{};
    for (std::size_t index = 0; index < id.size(); ++index) {
        id[index] = static_cast<std::byte>(0x10 + index);
    }
    options.archiveId = id;
    options.creationTimeNanoseconds = 1700000000000000000;
    options.workers = workers;
    return options;
}

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

std::vector<std::uint32_t> cutLengths(std::span<const std::byte> data, const CdcParams& params) {
    CdcSplitter splitter(params);
    std::vector<std::uint32_t> ends;
    for (std::byte value : data) {
        if (splitter.feed(value)) {
            ends.push_back(splitter.length());
            splitter.nextChunk();
        }
    }
    ends.push_back(splitter.length());
    return ends;
}

std::vector<std::byte> canonicalManifest(const Reader& reader) {
    Manifest manifest = reader.manifest();
    manifest.writer.workers = 1;
    std::vector<std::byte> out;
    REQUIRE(encodeManifest(manifest, out));
    return out;
}

Reader openArchive(const std::filesystem::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    return std::move(*reader);
}

}

TEST_CASE("cdc cuts match the published vectors") {
    CdcParams params{
        .min = 16,
        .target = 64,
        .max = 256,
    };

    std::string input;
    for (std::size_t round = 0; round < 2; ++round) {
        for (std::size_t value = 0; value < 256; ++value) {
            input.push_back(static_cast<char>(value));
        }
    }

    // NOTE: cross-checked against an independent Python implementation of the same table and
    // recurrence; the first cut at 45 shows hits below min are ignored, the tail shows a
    // short final chunk is kept whole.
    std::vector<std::uint32_t> expected{45, 62, 110, 28, 56, 62, 110, 28, 11};
    CHECK(cutLengths(bytesOf(input), params) == expected);

    CdcSplitter forced(defaultCdcParams);
    std::string zeros(std::size_t{5} * 1024 * 1024, '\0');
    std::vector<std::uint32_t> zeroEnds;
    for (std::byte value : bytesOf(zeros)) {
        if (forced.feed(value)) {
            zeroEnds.push_back(forced.length());
            forced.nextChunk();
        }
    }
    zeroEnds.push_back(forced.length());
    CHECK(zeroEnds == std::vector<std::uint32_t>{4 * 1024 * 1024, 1024 * 1024});
}

TEST_CASE("feed granularity does not move cdc boundaries") {
    std::string rep;
    std::string_view line = "line 42 of a compressible file\n";
    while (rep.size() < 614400) {
        rep += line;
    }
    rep.resize(614400);

    auto whole = cutLengths(bytesOf(rep), defaultCdcParams);
    CHECK(whole == std::vector<std::uint32_t>{614400});

    for (std::size_t step : {1U, 7U, 1000U, 70000U}) {
        CdcSplitter splitter(defaultCdcParams);
        std::vector<std::uint32_t> ends;
        for (std::size_t at = 0; at < rep.size(); at += step) {
            std::size_t end = std::min(at + step, rep.size());
            for (std::size_t index = at; index < end; ++index) {
                if (splitter.feed(static_cast<std::byte>(rep[index]))) {
                    ends.push_back(splitter.length());
                    splitter.nextChunk();
                }
            }
        }
        ends.push_back(splitter.length());
        CAPTURE(step);
        CHECK(ends == whole);
    }
}

TEST_CASE("a file written in pieces produces the same cdc archive as one written whole") {
    TempPath temp;
    std::filesystem::create_directories(temp.path());
    std::string content = noise(std::size_t{3} * 1024 * 1024, 99);

    auto whole = newWriter(temp.path() / "whole.bale", cdcOptions());
    REQUIRE(whole.addBytes("f", bytesOf(content)));
    REQUIRE(whole.finish());

    auto pieces = newWriter(temp.path() / "pieces.bale", cdcOptions());
    REQUIRE(pieces.beginFile("f"));
    for (std::size_t at = 0; at < content.size(); at += 1000) {
        REQUIRE(pieces.writeFile(bytesOf(std::string_view(content).substr(at, 1000))));
    }
    REQUIRE(pieces.endFile());
    REQUIRE(pieces.finish());

    CHECK(readAll(temp.path() / "whole.bale") == readAll(temp.path() / "pieces.bale"));
}

TEST_CASE("parallel workers write the same cdc records as one worker") {
    TempPath temp;
    std::filesystem::create_directories(temp.path());
    std::string content =
        noise(std::size_t{6} * 1024 * 1024, 7) + std::string(std::size_t{1} * 1024 * 1024, '\0');

    auto single = newWriter(temp.path() / "single.bale", cdcOptions(1));
    REQUIRE(single.addBytes("f", bytesOf(content)));
    auto expected = single.finish();
    REQUIRE(expected);

    auto parallel = newWriter(temp.path() / "parallel.bale", cdcOptions(8));
    REQUIRE(parallel.addBytes("f", bytesOf(content)));
    auto summary = parallel.finish();
    REQUIRE(summary);
    CHECK(summary->dataRecords == expected->dataRecords);
    CHECK(summary->chunkReferences == expected->chunkReferences);

    auto singleBytes = readAll(temp.path() / "single.bale");
    auto parallelBytes = readAll(temp.path() / "parallel.bale");
    Reader singleReader = openArchive(temp.path() / "single.bale");
    Reader parallelReader = openArchive(temp.path() / "parallel.bale");
    CHECK(singleReader.manifest().writer.workers == 1);
    CHECK(parallelReader.manifest().writer.workers == 8);
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
    CHECK(canonicalManifest(singleReader) == canonicalManifest(parallelReader));
    CHECK(parallelReader.verify(VerifyMode::Content));
}

TEST_CASE("a one-byte shift deduplicates with cdc but defeats fixed chunking") {
    TempPath temp;
    std::filesystem::create_directories(temp.path());
    std::string base = noise(std::size_t{3} * 1024 * 1024, 1234);
    std::string shifted = std::string(1, '\0') + base;

    auto fixed = newWriter(temp.path() / "fixed.bale");
    REQUIRE(fixed.addBytes("a", bytesOf(base)));
    REQUIRE(fixed.addBytes("b", bytesOf(shifted)));
    auto fixedSummary = fixed.finish();
    REQUIRE(fixedSummary);
    CHECK(fixedSummary->dataRecords == 7);

    auto cdc = newWriter(temp.path() / "cdc.bale", cdcOptions());
    REQUIRE(cdc.addBytes("a", bytesOf(base)));
    REQUIRE(cdc.addBytes("b", bytesOf(shifted)));
    auto cdcSummary = cdc.finish();
    REQUIRE(cdcSummary);
    CHECK(cdcSummary->chunkReferences == 2 * cdcSummary->dataRecords - 2);
    CHECK(cdcSummary->dataRecords < fixedSummary->dataRecords);
    CHECK(cdcSummary->archiveSize < fixedSummary->archiveSize);

    Reader reader = openArchive(temp.path() / "cdc.bale");
    REQUIRE(reader.verify(VerifyMode::Content));
    const auto& entries = reader.manifest().entries;
    REQUIRE(entries.size() == 2);
    CHECK(contents(reader, entries[0]) == base);
    CHECK(contents(reader, entries[1]) == shifted);
}

TEST_CASE("cdc chunk sizes stay within min and max on hostile inputs") {
    TempPath temp;
    std::filesystem::create_directories(temp.path());

    auto checkBounds = [&](const std::string& name, const std::string& data) {
        auto writer = newWriter(temp.path() / name, cdcOptions());
        REQUIRE(writer.addBytes("f", bytesOf(data)));
        auto summary = writer.finish();
        REQUIRE(summary);

        Reader reader = openArchive(temp.path() / name);
        REQUIRE(reader.verify(VerifyMode::Content));
        const auto& chunks = reader.manifest().chunks;
        REQUIRE(chunks.size() == summary->chunkReferences);
        for (std::size_t index = 0; index < chunks.size(); ++index) {
            CAPTURE(index);
            CHECK(chunks[index].length <= cdcMaxDefault);
            CHECK(chunks[index].length > 0);
            if (index + 1 < chunks.size()) {
                CHECK(chunks[index].length >= cdcMinDefault);
            }
        }
        CHECK(contents(reader, reader.manifest().entries[0]) == data);
    };

    checkBounds("zeros.bale", std::string(std::size_t{10} * 1024 * 1024, '\0'));
    checkBounds("random.bale", noise(std::size_t{10} * 1024 * 1024, 55));
    checkBounds("tiny.bale", std::string(100, 'x'));
    checkBounds("empty.bale", std::string());

    Reader zeros = openArchive(temp.path() / "zeros.bale");
    REQUIRE(zeros.manifest().chunks.size() == 3);
    CHECK(zeros.manifest().chunks[0].length == cdcMaxDefault);
    CHECK(zeros.manifest().chunks[1].length == cdcMaxDefault);
    CHECK(zeros.manifest().chunks[2].length == 2 * 1024 * 1024);

    Reader tiny = openArchive(temp.path() / "tiny.bale");
    REQUIRE(tiny.manifest().chunks.size() == 1);
    CHECK(tiny.manifest().chunks[0].length == 100);
}

TEST_CASE("invalid cdc sizes are refused before any chunk is stored") {
    TempPath base;
    std::filesystem::create_directories(base.path());

    auto expectLimit = [&](const char* name, CdcParams params) {
        auto file = File::createNew(base.path() / name);
        REQUIRE(file);
        WriterOptions options = cdcOptions();
        options.cdc = params;
        auto writer = Writer::create(std::move(*file), options);
        REQUIRE_FALSE(writer);
        CHECK(writer.error().kind == ErrorKind::LimitExceeded);
    };

    expectLimit(
        "order.bale",
        CdcParams{.min = 1024 * 1024, .target = 256 * 1024, .max = 1024 * 1024}
    );
    expectLimit(
        "target.bale",
        CdcParams{.min = 256 * 1024, .target = 8 * 1024 * 1024, .max = 4 * 1024 * 1024}
    );
    expectLimit(
        "small.bale",
        CdcParams{.min = 1024, .target = 1024 * 1024, .max = 4 * 1024 * 1024}
    );
    expectLimit(
        "huge.bale",
        CdcParams{.min = 256 * 1024, .target = 1024 * 1024, .max = 128 * 1024 * 1024}
    );
    expectLimit("zero.bale", CdcParams{.min = 0, .target = 0, .max = 0});
}

TEST_CASE("writer metadata round-trips the cdc triple next to codec and level") {
    WriterMetadata cdc = describeWriter(
        "bale",
        profileFor(Preset::Balanced),
        ChunkPolicy::Cdc,
        cdcTargetDefault,
        defaultCdcParams,
        4
    );
    CHECK(cdc.chunkPolicy == static_cast<std::uint64_t>(ChunkPolicy::Cdc));
    CHECK(cdc.chunkMin == cdcMinDefault);
    CHECK(cdc.chunkTarget == cdcTargetDefault);
    CHECK(cdc.chunkMax == cdcMaxDefault);
    CHECK(cdc.chunkAlgorithm == static_cast<std::uint64_t>(CdcAlgorithm::Gear));

    std::vector<std::byte> encoded;
    TlvWriter writer(encoded);
    std::vector<std::byte> scratch;
    REQUIRE(encodeWriterMetadata(cdc, 4, writer, scratch));

    TlvReader reader(encoded);
    TlvField field;
    auto more = reader.next(field);
    REQUIRE(more);
    REQUIRE(*more);

    auto decoded = decodeWriterMetadata(field);
    REQUIRE(decoded);

    TlvField end;
    auto done = reader.next(end);
    REQUIRE(done);
    CHECK_FALSE(*done);
    CHECK(decoded->chunkPolicy == cdc.chunkPolicy);
    CHECK(decoded->chunkMin == cdcMinDefault);
    CHECK(decoded->chunkTarget == cdcTargetDefault);
    CHECK(decoded->chunkMax == cdcMaxDefault);
    CHECK(decoded->chunkAlgorithm == static_cast<std::uint64_t>(CdcAlgorithm::Gear));

    WriterMetadata fixed = describeWriter("bale", profileFor(Preset::Small), 65536, 1);
    CHECK(fixed.chunkPolicy == static_cast<std::uint64_t>(ChunkPolicy::Fixed));
    CHECK_FALSE(fixed.chunkMin);
    CHECK_FALSE(fixed.chunkTarget);
    CHECK_FALSE(fixed.chunkMax);
    CHECK_FALSE(fixed.chunkAlgorithm);
}
