#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"

#include "archive/archive_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
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

namespace fs = std::filesystem;

namespace {

constexpr std::int64_t fileTime = 1700000000123456789;

// NOTE: the plain golden lives in tests/reference/plain.bale (see manifest.json);
// it is produced by tools/reference/make_goldens.py and shared with the Python verifier.
std::vector<std::byte> referencePlain() {
    return readAll(std::filesystem::path(REFERENCE_DIR) / "plain.bale");
}

void writeGoldenEntries(Writer& writer) {
    REQUIRE(writer.addDirectory("d", {.mtimeNanoseconds = 0, .mode = 0755}));
    REQUIRE(writer.addBytes("d/f", bytesOf("hello"), {.mtimeNanoseconds = fileTime, .mode = 0644}));
    REQUIRE(writer.addBytes("d/g", bytesOf("hello"), {.mtimeNanoseconds = fileTime, .mode = 0644}));
    REQUIRE(writer.addBytes("e", {}));
}

std::vector<std::byte> goldenFromWriter(const TempPath& temp) {
    auto writer = newWriter(temp.path());
    writeGoldenEntries(writer);
    REQUIRE(writer.finish());
    return readAll(temp.path());
}

Result<Reader> openBytes(std::span<const std::byte> bytes, const ReaderOptions& options = {}) {
    TempFile file(bytes);
    REQUIRE(file.ok());
    auto opened = file.open();
    REQUIRE(opened);
    return Reader::open(std::move(*opened), options);
}

void writeText(const fs::path& path, std::string_view text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
}

std::string pattern(std::size_t length) {
    std::string out(length, '\0');
    for (std::size_t index = 0; index < length; ++index) {
        out[index] = static_cast<char>((index * 7 + index / 251) & 0xFF);
    }
    return out;
}

void rewriteCrc(std::vector<std::byte>& bytes, std::uint64_t recordOffset, std::uint64_t length) {
    auto payload = std::span(bytes).subspan(
        static_cast<std::size_t>(recordOffset + recordPrefixSize),
        static_cast<std::size_t>(length - recordFramingSize)
    );
    storeLe(payload.data() + payload.size(), Crc32c::of(payload));
}

class Assembler {
  public:
    Assembler() {
        auto superblock = encodeSuperblock(Superblock{});
        out_.assign(superblock.begin(), superblock.end());
    }

    RecordReference add(RecordType type, std::span<const std::byte> payload) {
        RecordHeader header;
        header.type = type;
        header.payloadLength = payload.size();
        header.decodedLength = payload.size();
        header.sequence = sequence_++;
        auto prefix = encodeRecordPrefix(header);
        auto trailer = encodeRecordTrailer(Crc32c::of(payload));

        RecordReference reference{
            .offset = out_.size(),
            .length = recordFramingSize + payload.size(),
        };
        out_.insert(out_.end(), prefix.begin(), prefix.end());
        out_.insert(out_.end(), payload.begin(), payload.end());
        out_.insert(out_.end(), trailer.begin(), trailer.end());
        return reference;
    }

    RecordReference addData(std::string_view chunk) {
        std::vector<std::byte> payload;
        REQUIRE(encodeDataDescriptor(chunkKeyOf(bytesOf(chunk)), payload));
        auto bytes = bytesOf(chunk);
        payload.insert(payload.end(), bytes.begin(), bytes.end());
        return add(RecordType::Data, payload);
    }

    RecordReference addManifest(const Manifest& manifest) {
        std::vector<std::byte> payload;
        REQUIRE(encodeManifest(manifest, payload));
        auto reference = add(RecordType::Manifest, payload);
        reference.digest = Blake3::of(HashDomain::Manifest, payload);
        return reference;
    }

    RecordReference addIndex(std::vector<IndexEntry> entries) {
        std::ranges::sort(entries, {}, &IndexEntry::key);
        std::vector<std::byte> payload;
        REQUIRE(encodeIndex(entries, payload));
        auto reference = add(RecordType::Index, payload);
        reference.digest = Blake3::of(HashDomain::Index, payload);
        return reference;
    }

    std::vector<std::byte> finish(const Commit& commit) {
        std::vector<std::byte> payload;
        REQUIRE(encodeCommit(commit, payload));
        auto reference = add(RecordType::Commit, payload);

        Footer footer;
        footer.commitOffset = reference.offset;
        footer.commitLength = reference.length;
        footer.generation = commit.generation;
        footer.commitDigest = Blake3::of(HashDomain::Commit, payload);
        auto encoded = encodeFooter(footer);
        out_.insert(out_.end(), encoded.begin(), encoded.end());
        return out_;
    }

  private:
    std::vector<std::byte> out_;
    std::uint64_t sequence_ = 0;
};

Manifest singleFile(std::string_view chunk) {
    Manifest manifest;
    manifest.chunks.push_back(chunkKeyOf(bytesOf(chunk)));
    manifest.entries.push_back(
        ManifestEntry{
            .path = "f",
            .length = chunk.size(),
            .chunkCount = 1,
            .kind = EntryKind::Regular,
        }
    );
    return manifest;
}

IndexEntry indexed(std::string_view chunk, const RecordReference& record) {
    return IndexEntry{
        .key = chunkKeyOf(bytesOf(chunk)),
        .recordOffset = record.offset,
        .recordLength = record.length,
    };
}

}

TEST_CASE("writer output matches the independently encoded golden archive byte for byte") {
    TempPath temp;
    auto written = goldenFromWriter(temp);
    CHECK(written == referencePlain());

    auto reader = openBytes(referencePlain());
    REQUIRE(reader);
    CHECK(reader->superblock().creationTimeNs == 1700000000000000000);
    CHECK(reader->ignoredTrailingBytes() == 0);
    CHECK(reader->index().size() == 1);

    const auto& entries = reader->manifest().entries;
    REQUIRE(entries.size() == 4);
    CHECK(entries[0].path == "d");
    CHECK(entries[0].mode == 0755);
    CHECK(entries[1].path == "d/f");
    CHECK(entries[1].mtimeNanoseconds == fileTime);
    CHECK(contents(*reader, entries[1]) == "hello");
    CHECK(contents(*reader, entries[2]) == "hello");
    CHECK(entries[3].length == 0);
    CHECK(contents(*reader, entries[3]).empty());

    auto report = reader->verify(VerifyMode::Content);
    REQUIRE(report);
    CHECK(report->records == 4);
    CHECK(report->dataRecords == 1);
    CHECK(report->chunksVerified == 1);
    CHECK(report->bytesVerified == 5);
}

TEST_CASE("a nested tree round-trips with deduplicated chunks, empty files and links") {
    TempPath temp;
    fs::path root = temp.path() / "tree";
    fs::create_directories(root / "a" / "b" / "c");
    fs::create_directories(root / "emptydir");
    std::string big = pattern(std::size_t{3} * 4096 + 100);
    writeText(root / "a" / "b" / "c" / "deep.bin", big);
    writeText(root / "a" / "copy.bin", big);
    writeText(root / "a" / "half.bin", big.substr(0, 8192));
    writeText(root / "empty.txt", "");
    writeText(root / "zeros.bin", std::string(std::size_t{3} * 4096, '\0'));
#ifndef _WIN32
    fs::create_symlink("a/copy.bin", root / "link");
    fs::create_hard_link(root / "zeros.bin", root / "hard");
#endif

    fs::path archivePath = temp.path() / "out.bale";
    auto writer = newWriter(archivePath, fixedOptions(minChunkSize));
    REQUIRE(writer.addTree(root, archivePath));
    CHECK(writer.skipped().empty());
    auto summary = writer.finish();
    REQUIRE(summary);
    CHECK(summary->dataRecords == 5);
    CHECK(summary->chunkReferences == 13);

    auto file = File::openRead(archivePath);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    CHECK(reader->index().size() == 5);

    std::vector<std::string_view> paths;
    for (const auto& entry : reader->manifest().entries) {
        paths.push_back(entry.path);
    }
#ifndef _WIN32
    std::vector<std::string_view> expected{
        "a",
        "a/b",
        "a/b/c",
        "a/b/c/deep.bin",
        "a/copy.bin",
        "a/half.bin",
        "empty.txt",
        "emptydir",
        "hard",
        "link",
        "zeros.bin",
    };
#else
    std::vector<std::string_view> expected{
        "a",
        "a/b",
        "a/b/c",
        "a/b/c/deep.bin",
        "a/copy.bin",
        "a/half.bin",
        "empty.txt",
        "emptydir",
        "zeros.bin",
    };
#endif
    CHECK(paths == expected);

    const auto& entries = reader->manifest().entries;
    auto entry = [&](std::string_view path) -> const ManifestEntry& {
        const auto* found = findEntry(entries, path);
        REQUIRE(found != nullptr);
        return *found;
    };
    CHECK(contents(*reader, entry("a/b/c/deep.bin")) == big);
    CHECK(contents(*reader, entry("a/copy.bin")) == big);
    CHECK(contents(*reader, entry("a/half.bin")) == big.substr(0, 8192));
    CHECK(entry("empty.txt").length == 0);
    CHECK(entry("emptydir").kind == EntryKind::Directory);
    CHECK(entry("a/copy.bin").mtimeNanoseconds.has_value());
#ifndef _WIN32
    CHECK(entry("link").kind == EntryKind::Symlink);
    CHECK(entry("link").target == "a/copy.bin");
    CHECK(entry("hard").kind == EntryKind::Regular);
    CHECK(contents(*reader, entry("hard")) == std::string(std::size_t{3} * 4096, '\0'));
    CHECK(entry("zeros.bin").kind == EntryKind::HardLink);
    CHECK(entry("zeros.bin").target == "hard");
#endif

    auto report = reader->verify(VerifyMode::Content);
    REQUIRE(report);
    CHECK(report->dataRecords == 5);
    CHECK(report->unindexedDataRecords == 0);
    CHECK(report->chunksVerified == 5);
}

TEST_CASE("writing the same tree twice with fixed identity produces identical bytes") {
    TempPath temp;
    fs::path root = temp.path() / "tree";
    fs::create_directories(root / "x" / "y");
    fs::create_directories(root / "m");
    for (std::size_t index = 0; index < 20; ++index) {
        writeText(root / "x" / ("f" + std::to_string(index)), pattern(index * 997));
        writeText(root / "m" / ("g" + std::to_string(19 - index)), pattern(index * 13));
    }

    std::vector<std::vector<std::byte>> outputs;
    for (const char* name : {"one.bale", "two.bale"}) {
        auto writer = newWriter(temp.path() / name, fixedOptions(minChunkSize));
        REQUIRE(writer.addTree(root));
        REQUIRE(writer.finish());
        outputs.push_back(readAll(temp.path() / name));
    }
    REQUIRE(outputs[0].size() > 1000);
    CHECK(outputs[0] == outputs[1]);
}

TEST_CASE("a file written in pieces produces the same archive as one written whole") {
    TempPath temp;
    fs::create_directories(temp.path());
    std::string content = pattern(minChunkSize * 3 + 123);

    auto whole = newWriter(temp.path() / "whole.bale", fixedOptions(minChunkSize));
    REQUIRE(whole.addBytes("f", bytesOf(content)));
    REQUIRE(whole.finish());

    auto pieces = newWriter(temp.path() / "pieces.bale", fixedOptions(minChunkSize));
    REQUIRE(pieces.beginFile("f"));
    CHECK(pieces.addDirectory("d").error().kind == ErrorKind::Malformed);
    for (std::size_t at = 0; at < content.size(); at += 1000) {
        REQUIRE(pieces.writeFile(bytesOf(std::string_view(content).substr(at, 1000))));
    }
    REQUIRE(pieces.endFile());
    REQUIRE(pieces.finish());

    CHECK(readAll(temp.path() / "whole.bale") == readAll(temp.path() / "pieces.bale"));
}

TEST_CASE("an empty archive has only metadata records and verifies") {
    TempPath temp;
    auto writer = newWriter(temp.path());
    auto summary = writer.finish();
    REQUIRE(summary);
    CHECK(summary->archiveSize == 499);
    CHECK(writer.addBytes("late", bytesOf("x")).error().kind == ErrorKind::Malformed);

    auto file = File::openRead(temp.path());
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    CHECK(reader->manifest().entries.empty());
    CHECK(reader->index().empty());
    auto report = reader->verify(VerifyMode::Content);
    REQUIRE(report);
    CHECK(report->records == 3);
    CHECK(report->chunksVerified == 0);
}

TEST_CASE("hard links are rewritten so the first path in byte order owns the content") {
    TempPath temp;
    auto writer = newWriter(temp.path());
    REQUIRE(writer.addBytes("z", bytesOf("data"), {.mtimeNanoseconds = 7, .mode = 0600}));
    REQUIRE(writer.addHardLink("m", "z"));
    REQUIRE(writer.addHardLink("a", "z"));
    REQUIRE(writer.addSymlink("s", "../outside", {.mtimeNanoseconds = 3}));
    REQUIRE(writer.finish());

    auto file = File::openRead(temp.path());
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    const auto& entries = reader->manifest().entries;
    REQUIRE(entries.size() == 4);
    CHECK(entries[0].path == "a");
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(entries[0].mode == 0600);
    CHECK(entries[0].mtimeNanoseconds == 7);
    CHECK(contents(*reader, entries[0]) == "data");
    CHECK(entries[1].kind == EntryKind::HardLink);
    CHECK(entries[1].target == "a");
    CHECK(entries[2].target == "../outside");
    CHECK(entries[3].kind == EntryKind::HardLink);
    CHECK(entries[3].target == "a");
    CHECK_FALSE(entries[3].mode);
}

TEST_CASE("writer refuses bad options, paths and inconsistent entry sets") {
    TempPath base;
    fs::create_directories(base.path());

    for (std::uint32_t size : {minChunkSize - 1, maxChunkSize + 1}) {
        auto file = File::createNew(base.path() / ("size" + std::to_string(size)));
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), fixedOptions(size));
        REQUIRE_FALSE(writer);
        CHECK(writer.error().kind == ErrorKind::LimitExceeded);
    }

    auto usable = newWriter(base.path() / "usable.bale");
    CHECK(usable.addBytes("../x", bytesOf("x")).error().kind == ErrorKind::UnsafePath);
    CHECK(usable.addDirectory("a/", {}).error().kind == ErrorKind::UnsafePath);
    CHECK(usable.addDirectory("a", {.mode = 0170755}).error().kind == ErrorKind::Malformed);
    CHECK(usable.addSymlink("s", "").error().kind == ErrorKind::UnsafePath);
    REQUIRE(usable.addBytes("ok", bytesOf("x")));
    CHECK(usable.finish());

    auto expectFinishError = [&](const char* name, auto&& populate) {
        auto writer = newWriter(base.path() / name);
        populate(writer);
        auto finished = writer.finish();
        REQUIRE_FALSE(finished);
        CHECK(finished.error().kind == ErrorKind::Malformed);
        CHECK(writer.finish().error().what == finished.error().what);
    };
    expectFinishError("dup.bale", [](Writer& writer) {
        REQUIRE(writer.addBytes("a", bytesOf("1")));
        REQUIRE(writer.addBytes("a", bytesOf("2")));
    });
    expectFinishError("orphan.bale", [](Writer& writer) {
        REQUIRE(writer.addBytes("x/y", bytesOf("1")));
    });
    expectFinishError("dangling.bale", [](Writer& writer) {
        REQUIRE(writer.addHardLink("b", "missing"));
    });
}

TEST_CASE("content verification detects a flipped chunk byte by CRC and by BLAKE3") {
    TempPath temp;
    auto golden = goldenFromWriter(temp);
    auto reader = openBytes(golden);
    REQUIRE(reader);
    const IndexEntry record = reader->index()[0];
    auto lastChunkByte = static_cast<std::size_t>(record.recordOffset + record.recordLength - 9);

    auto flipped = golden;
    flipped[lastChunkByte] ^= std::byte{0x01};
    auto damaged = openBytes(flipped);
    REQUIRE(damaged);
    CHECK(damaged->verify(VerifyMode::Structure));
    auto content = damaged->verify(VerifyMode::Content);
    REQUIRE_FALSE(content);
    CHECK(content.error().kind == ErrorKind::Integrity);
    CHECK(content.error().what == "record payload checksum mismatch");

    rewriteCrc(flipped, record.recordOffset, record.recordLength);
    auto forged = openBytes(flipped);
    REQUIRE(forged);
    auto forgedContent = forged->verify(VerifyMode::Content);
    REQUIRE_FALSE(forgedContent);
    CHECK(forgedContent.error().kind == ErrorKind::Integrity);
    CHECK(forgedContent.error().what == "chunk content does not match its BLAKE3 digest");

    auto streamed = forged->streamFile(forged->manifest().entries[1], [](auto) {
        return Result<void>{};
    });
    REQUIRE_FALSE(streamed);
    CHECK(streamed.error().kind == ErrorKind::Integrity);
}

TEST_CASE("a modified manifest, index or commit is rejected at open") {
    TempPath temp;
    auto golden = goldenFromWriter(temp);
    auto reader = openBytes(golden);
    REQUIRE(reader);
    Commit commit = reader->commit();
    std::uint64_t footerOffset = reader->footerOffset();

    struct Target {
        std::uint64_t offset;
        std::uint64_t length;
        std::string_view digestError;
    };
    for (const Target& target : {
             Target{commit.manifest.offset, commit.manifest.length, "manifest digest mismatch"},
             Target{commit.index.offset, commit.index.length, "index digest mismatch"},
             Target{footerOffset - 182, 182, "commit digest mismatch"},
         }) {
        CAPTURE(target.digestError);
        auto flipped = golden;
        flipped[static_cast<std::size_t>(target.offset + recordPrefixSize + 1)] ^= std::byte{0x02};
        auto damaged = openBytes(flipped);
        REQUIRE_FALSE(damaged);
        CHECK(damaged.error().kind == ErrorKind::Integrity);
        CHECK(damaged.error().what == "record payload checksum mismatch");

        rewriteCrc(flipped, target.offset, target.length);
        auto forged = openBytes(flipped);
        REQUIRE_FALSE(forged);
        CHECK(forged.error().kind == ErrorKind::Integrity);
        CHECK(forged.error().what == target.digestError);
    }
}

TEST_CASE("an interrupted or truncated archive fails with a clear missing-footer error") {
    TempPath temp;
    {
        auto writer = newWriter(temp.path(), fixedOptions(minChunkSize));
        REQUIRE(writer.addBytes("big", bytesOf(pattern(std::size_t{5} * 4096))));
        REQUIRE(writer.addBytes("small", bytesOf("abc")));
    }
    auto interrupted = File::openRead(temp.path());
    REQUIRE(interrupted);
    auto opened = Reader::open(std::move(*interrupted));
    REQUIRE_FALSE(opened);
    CHECK(opened.error().kind == ErrorKind::Truncated);
    CHECK(opened.error().what == "no footer found: the archive is incomplete or truncated");

    auto golden = referencePlain();
    for (std::size_t size = 0; size < golden.size(); ++size) {
        CAPTURE(size);
        auto truncated = openBytes(std::span(golden).first(size));
        REQUIRE_FALSE(truncated);
        CHECK(
            (truncated.error().kind == ErrorKind::Truncated ||
             truncated.error().kind == ErrorKind::Malformed)
        );
    }
}

TEST_CASE("footer discovery skips trailing garbage and fake footers within the window") {
    auto golden = referencePlain();

    auto garbage = golden;
    garbage.insert(garbage.end(), 1000, std::byte{0xAB});
    std::ranges::copy(
        footerMagic,
        garbage.begin() + static_cast<std::ptrdiff_t>(golden.size() + 500)
    );
    auto reader = openBytes(garbage);
    REQUIRE(reader);
    CHECK(reader->ignoredTrailingBytes() == 1000);
    CHECK(reader->verify(VerifyMode::Content));

    ReaderOptions narrow;
    narrow.footerScanBlockSize = 512;
    auto recovered = openBytes(garbage, narrow);
    REQUIRE(recovered);
    CHECK(recovered->ignoredTrailingBytes() == 1000);

    auto replayed = golden;
    replayed.insert(replayed.end(), 10, std::byte{0});
    replayed.insert(replayed.end(), golden.end() - 96, golden.end());
    auto skipped = openBytes(replayed);
    REQUIRE(skipped);
    CHECK(skipped->ignoredTrailingBytes() == 106);
    CHECK(skipped->footerOffset() == golden.size() - 96);
}

TEST_CASE("footer discovery recovers past an interrupted append larger than the scan window") {
    auto bytes = referencePlain();
    bytes.resize(bytes.size() + (2U << 20), std::byte{0xA5});

    ReaderOptions options;
    options.footerScanBlockSize = 512;
    auto reader = openBytes(bytes, options);
    REQUIRE(reader);
    CHECK(reader->commit().generation == 1);
    CHECK(reader->ignoredTrailingBytes() == (2U << 20));
}

TEST_CASE("cross-record inconsistencies are rejected even when every digest is valid") {
    SUBCASE("manifest references a chunk the index lacks") {
        Assembler assembler;
        auto data = assembler.addData("hello");
        Commit commit;
        commit.manifest = assembler.addManifest(singleFile("other"));
        commit.index = assembler.addIndex({indexed("hello", data)});
        auto opened = openBytes(assembler.finish(commit));
        REQUIRE_FALSE(opened);
        CHECK(opened.error().what == "manifest references a chunk missing from the index");
    }

    SUBCASE("indexed record overlaps the manifest") {
        Assembler assembler;
        auto data = assembler.addData("hello");
        Commit commit;
        commit.manifest = assembler.addManifest(singleFile("hello"));
        auto overlapping = data;
        overlapping.offset = commit.manifest.offset;
        IndexEntry entry = indexed("hello", overlapping);
        commit.index = assembler.addIndex({entry});
        auto opened = openBytes(assembler.finish(commit));
        REQUIRE_FALSE(opened);
        CHECK(opened.error().kind == ErrorKind::Malformed);
    }

    SUBCASE("a generation without a valid parent is rejected") {
        Assembler assembler;
        auto data = assembler.addData("hello");
        Commit commit;
        commit.generation = 2;
        commit.previous[0] = std::byte{1};
        commit.manifest = assembler.addManifest(singleFile("hello"));
        commit.index = assembler.addIndex({indexed("hello", data)});
        auto opened = openBytes(assembler.finish(commit));
        REQUIRE_FALSE(opened);
        CHECK(opened.error().kind == ErrorKind::Malformed);
    }

    SUBCASE("swapped index locations are caught when the chunk is read") {
        Assembler assembler;
        auto hello = assembler.addData("hello");
        auto world = assembler.addData("world");
        Commit commit;
        commit.manifest = assembler.addManifest(singleFile("hello"));
        commit.index = assembler.addIndex({indexed("hello", world), indexed("world", hello)});
        auto opened = openBytes(assembler.finish(commit));
        REQUIRE(opened);
        CHECK(opened->verify(VerifyMode::Structure));
        auto content = opened->verify(VerifyMode::Content);
        REQUIRE_FALSE(content);
        CHECK(content.error().what == "data record holds a different chunk than indexed");
    }

    SUBCASE("an index offset inside another record is not a record boundary") {
        Assembler assembler;
        auto filler = assembler.addData("0123456789");
        auto hello = assembler.addData("hello");
        Commit commit;
        commit.manifest = assembler.addManifest(singleFile("hello"));
        auto shifted = hello;
        shifted.offset = filler.offset + 5;
        commit.index = assembler.addIndex({indexed("hello", shifted)});
        auto opened = openBytes(assembler.finish(commit));
        REQUIRE(opened);
        auto structure = opened->verify(VerifyMode::Structure);
        REQUIRE_FALSE(structure);
        CHECK(structure.error().what == "index entry does not point at a record boundary");
        CHECK_FALSE(opened->streamFile(opened->manifest().entries[0], [](auto) {
            return Result<void>{};
        }));
    }
}
