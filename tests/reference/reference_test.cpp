// Differential tests against the independent Python reference implementation.
// Every golden under tests/reference was produced by
// tools/reference/make_goldens.py (stdlib only, written from the schema
// description). Goldens with raw-codec data records are rebuilt here with the
// C++ writer and must come out byte-identical; codec goldens embed genuine
// C++ encoder output and are read back; corrupt fixtures must fail with the
// same kind and message the Python verifier reports (see manifest.json).

#include "archive/chunk_codec.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"

#include "archive/archive_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <filesystem>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::contents;
using bale::test::fixedOptions;
using bale::test::newWriter;
using bale::test::readAll;
using bale::test::TempFile;
using bale::test::TempPath;

namespace {

constexpr std::int64_t fileTime = 1700000000123456789;

std::vector<std::byte> referenceFile(const char* name) {
    return readAll(std::filesystem::path(REFERENCE_DIR) / name);
}

Result<Reader> openBytes(std::span<const std::byte> bytes) {
    TempFile file(bytes);
    if (!file.ok()) {
        return fail(ErrorKind::Malformed, "could not stage reference bytes");
    }
    auto opened = file.open();
    if (!opened) {
        return std::unexpected(opened.error());
    }
    return Reader::open(std::move(*opened));
}

std::string cdcNoise(std::size_t length, std::uint32_t seed) {
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

std::string repeated(char letter, std::size_t count) {
    return std::string(count, letter);
}

WriterOptions cdcReferenceOptions() {
    WriterOptions options = fixedOptions();
    options.chunkPolicy = ChunkPolicy::Cdc;
    options.cdc = CdcParams{.min = 4096, .target = 8192, .max = 65536};
    options.compression =
        CompressionProfile{.preset = std::nullopt, .codec = CodecId::Raw, .level = 0};
    return options;
}

void checkContents(Reader& reader) {
    auto entry = [&](std::string_view path) {
        const auto* found = findEntry(reader.manifest().entries, path);
        REQUIRE(found != nullptr);
        return found;
    };
    CHECK(contents(reader, *entry("brotli")) == repeated('x', 4096));
    CHECK(contents(reader, *entry("lz4")) == repeated('v', 4096));
    CHECK(contents(reader, *entry("lzma2")) == repeated('w', 4096));
    CHECK(contents(reader, *entry("raw")) == repeated('t', 4096));
    CHECK(contents(reader, *entry("zstd")) == repeated('u', 4096));
}

} // namespace

TEST_CASE("reference plain golden rebuilds byte-identical and reads back") {
    TempPath temp;
    auto writer = newWriter(temp.path());
    REQUIRE(writer.addDirectory("d", {.mtimeNanoseconds = 0, .mode = 0755}));
    REQUIRE(writer.addBytes("d/f", bytesOf("hello"), {.mtimeNanoseconds = fileTime, .mode = 0644}));
    REQUIRE(writer.addBytes("d/g", bytesOf("hello"), {.mtimeNanoseconds = fileTime, .mode = 0644}));
    REQUIRE(writer.addBytes("e", {}));
    REQUIRE(writer.finish());
    CHECK(readAll(temp.path()) == referenceFile("plain.bale"));

    auto reader = openBytes(referenceFile("plain.bale"));
    REQUIRE(reader);
    REQUIRE(reader->manifest().entries.size() == 4);
    CHECK(contents(*reader, reader->manifest().entries[1]) == "hello");
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("reference cdc golden rebuilds byte-identical and deduplicates the copy") {
    std::string data = cdcNoise(93000, 99);

    TempPath temp;
    auto file = File::createNew(temp.path());
    REQUIRE(file);
    auto writer = Writer::create(std::move(*file), cdcReferenceOptions());
    REQUIRE(writer);
    REQUIRE(writer->addDirectory("a", {}));
    REQUIRE(writer->addBytes("a/data.bin", bytesOf(data)));
    REQUIRE(writer->addBytes("a/copy.bin", bytesOf(data)));
    auto summary = writer->finish();
    REQUIRE(summary);
    CHECK(summary->dataRecords < summary->chunkReferences);
    CHECK(readAll(temp.path()) == referenceFile("cdc.bale"));

    auto reader = openBytes(referenceFile("cdc.bale"));
    REQUIRE(reader);
    CHECK(reader->manifest().writer.chunkPolicy == static_cast<std::uint64_t>(ChunkPolicy::Cdc));
    CHECK(reader->manifest().writer.chunkMin == 4096);
    CHECK(reader->manifest().writer.chunkTarget == 8192);
    CHECK(reader->manifest().writer.chunkMax == 65536);
    REQUIRE(reader->manifest().entries.size() == 3);
    CHECK(contents(*reader, reader->manifest().entries[1]) == data);
    CHECK(contents(*reader, reader->manifest().entries[2]) == data);
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("reference codec golden reads back every codec") {
    auto reader = openBytes(referenceFile("codecs.bale"));
    REQUIRE(reader);
    REQUIRE(reader->manifest().entries.size() == 5);
    REQUIRE(reader->index().size() == 5);
    checkContents(*reader);
    auto report = reader->verify(VerifyMode::Content);
    REQUIRE(report);
    CHECK(report->chunksVerified == 5);
    CHECK(report->bytesVerified == 5 * 4096);
}

TEST_CASE("reference two-generation golden rebuilds byte-identical") {
    TempPath temp;
    {
        auto writer = newWriter(temp.path());
        REQUIRE(writer.addBytes("old", bytesOf("v1-bytes")));
        REQUIRE(writer.finish());
    }
    {
        auto file = File::openAppend(temp.path());
        REQUIRE(file);
        auto writer = Writer::append(std::move(*file), fixedOptions());
        REQUIRE(writer);
        REQUIRE(writer->addBytes("new", bytesOf("v1-bytes")));
        REQUIRE(writer->finish());
    }
    CHECK(readAll(temp.path()) == referenceFile("snapshot2.bale"));

    auto reader = openBytes(referenceFile("snapshot2.bale"));
    REQUIRE(reader);
    CHECK(reader->commit().generation == 2);
    REQUIRE(reader->manifest().entries.size() == 1);
    CHECK(reader->manifest().entries.front().path == "new");
    CHECK(contents(*reader, reader->manifest().entries.front()) == "v1-bytes");
    CHECK(reader->index().size() == 1);
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("reference metadata golden rebuilds byte-identical with the link rewrite") {
    TempPath temp;
    auto file = File::createNew(temp.path());
    REQUIRE(file);
    WriterOptions options = fixedOptions(65536);
    options.compression = profileFor(Preset::Small);
    options.comment = "snapshot comment";
    auto writer = Writer::create(std::move(*file), options);
    REQUIRE(writer);
    REQUIRE(writer->addDirectory("d", {.mtimeNanoseconds = 0, .mode = 0755}));
    REQUIRE(
        writer->addBytes("d/f", bytesOf("hello"), {.mtimeNanoseconds = fileTime, .mode = 0644})
    );
    REQUIRE(writer->addBytes("e", {}));
    REQUIRE(writer->addHardLink("a", "z"));
    REQUIRE(writer->addHardLink("h", "d/f"));
    REQUIRE(writer->addSymlink("l", "d/f", {.mtimeNanoseconds = 1}));
    REQUIRE(writer->addBytes("z", bytesOf("data"), {.mtimeNanoseconds = 7, .mode = 0600}));
    REQUIRE(writer->finish());
    CHECK(readAll(temp.path()) == referenceFile("meta.bale"));

    auto reader = openBytes(referenceFile("meta.bale"));
    REQUIRE(reader);
    CHECK(reader->manifest().comment == "snapshot comment");
    CHECK(reader->manifest().writer.level == 19);
    const auto& entries = reader->manifest().entries;
    REQUIRE(entries.size() == 7);
    CHECK(entries[0].path == "a");
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(contents(*reader, entries[0]) == "data");
    CHECK(entries[6].kind == EntryKind::HardLink);
    CHECK(entries[6].target == "a");
    CHECK(entries[5].kind == EntryKind::Symlink);
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("reference encrypted envelope stops without a key") {
    auto reader = openBytes(referenceFile("encrypted-structure.bale"));
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::PasswordRequired);
}

TEST_CASE("reference corrupt fixtures fail with the pinned verdicts") {
    struct Expectation {
        const char* file;
        bool openFails;
        ErrorKind kind;
        std::string_view what;
    };
    // NOTE: `what` strings are shared with tools/reference/bale_verify.py; both
    // sides pin kind and message, the stage (open vs verify) is incidental.
    const Expectation expectations[] = {
        {"corrupt-bad-magic.bale", true, ErrorKind::Malformed, "not a bale archive"},
        {"corrupt-small-file.bale", true, ErrorKind::Truncated, "file too small for a superblock"},
        {"corrupt-truncated.bale", true, ErrorKind::Truncated, "no footer found"},
        {"corrupt-manifest-digest.bale", true, ErrorKind::Integrity, "manifest digest mismatch"},
        {"corrupt-commit-digest.bale", true, ErrorKind::Integrity, "commit digest mismatch"},
        {"corrupt-unknown-feature.bale", true, ErrorKind::Unsupported, "unknown required feature"},
        {"corrupt-bad-record-type.bale", true, ErrorKind::Unsupported, "unknown record type"},
        {"corrupt-payload-crc.bale",
         false,
         ErrorKind::Integrity,
         "record payload checksum mismatch"},
        {"corrupt-payload-crc-fixed.bale",
         false,
         ErrorKind::Integrity,
         "chunk content does not match"},
        {"corrupt-unknown-flag.bale",
         false,
         ErrorKind::Unsupported,
         "unknown required record flag"},
        {"corrupt-encrypted-in-plain.bale",
         false,
         ErrorKind::Unsupported,
         "encrypted record in a plain archive"},
    };
    for (const auto& expected : expectations) {
        CAPTURE(expected.file);
        auto reader = openBytes(referenceFile(expected.file));
        if (expected.openFails) {
            REQUIRE_FALSE(reader);
            CHECK(reader.error().kind == expected.kind);
            CHECK(std::string(reader.error().what).find(expected.what) != std::string::npos);
        } else {
            REQUIRE(reader);
            auto report = reader->verify(VerifyMode::Content);
            REQUIRE_FALSE(report);
            CHECK(report.error().kind == expected.kind);
            CHECK(std::string(report.error().what).find(expected.what) != std::string::npos);
        }
    }
}
