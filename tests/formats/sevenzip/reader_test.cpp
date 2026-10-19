#include "formats/sevenzip/reader.hpp"

#include "formats/detect.hpp"
#include "formats/sevenzip/sevenzip_fixture.hpp"

#include <doctest/doctest.h>

#include <array>
#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace bale;
using namespace bale::sevenzip::test;

namespace {

// NOTE: every binary fixture below is built in code by sevenzip_fixture.hpp,
// which mirrors the layout 7-Zip 26.04 writes (verified byte by byte against
// `7z a -t7z` output during development). No checked-in binaries.

Result<sevenzip::Reader> openSevenZip(const TempFile& temp, const sevenzip::Limits& limits = {}) {
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    return sevenzip::Reader::open(std::move(*file), limits);
}

std::vector<sevenzip::Entry> collect(const sevenzip::Reader& reader) {
    std::vector<sevenzip::Entry> entries(reader.entries().begin(), reader.entries().end());
    return entries;
}

Result<std::string>
streamText(sevenzip::Reader& reader, const sevenzip::Entry& entry, std::size_t scratchSize = 256) {
    std::vector<std::byte> scratch(scratchSize);
    std::string text;
    auto streamed = reader.streamEntry(entry, scratch, [&](std::span<const std::byte> chunk) {
        text.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    if (!streamed) {
        return std::unexpected(streamed.error());
    }
    return text;
}

std::string readAll(sevenzip::Reader& reader, const sevenzip::Entry& entry) {
    auto text = streamText(reader, entry);
    REQUIRE(text);
    return *text;
}

SevenZipSpec mixedSpec() {
    SevenZipSpec spec;
    spec.entries.push_back({.name = "docs", .dir = true, .mtime = 1'700'000'000});
    spec.entries.push_back({.name = "docs/readme.txt", .data = "hello, stored world\n"});
    spec.entries.push_back({.name = "docs/empty.txt", .data = "", .emptyFile = true});
    spec.entries.push_back({.name = "docs/café.txt", .data = "utf-8 name\n"});
    spec.entries.push_back({.name = "docs/gone.txt", .data = "", .anti = true});
    return spec;
}

void checkRejected(
    const Bytes& bytes,
    ErrorKind kind,
    std::string_view what,
    const sevenzip::Limits& limits = {}
) {
    TempFile temp(bytes);
    auto reader = openSevenZip(temp, limits);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == kind);
    CHECK(reader.error().what == what);
}

void patchHeaderByte(BuiltSevenZip& built, std::size_t at, std::byte value) {
    built.bytes[at] = value;
    std::span<const std::byte> header(built.bytes.data() + built.headerStart, built.headerSize);
    patch32(built.bytes, 28, Crc32::of(header));
    std::span<const std::byte> start(built.bytes.data() + 12, 20);
    patch32(built.bytes, 8, Crc32::of(start));
}

}

TEST_CASE("7z reader lists mixed entries with metadata and reads their data") {
    auto built = buildSevenZip(mixedSpec());
    TempFile temp(built.bytes);
    auto reader = openSevenZip(temp);
    REQUIRE(reader);
    CHECK(reader->entryCount() == 4);
    CHECK(reader->folderCount() == 1);

    auto entries = collect(*reader);
    REQUIRE(entries.size() == 4);
    CHECK(entries[0].name == "docs");
    CHECK(entries[0].directory);
    CHECK(entries[0].size == 0);
    CHECK_FALSE(entries[0].folder);
    CHECK(entries[0].mode == 040755);
    CHECK(entries[0].mtimeNanoseconds == 1'700'000'000'000'000'000LL);
    CHECK(entries[1].name == "docs/readme.txt");
    CHECK_FALSE(entries[1].directory);
    CHECK(entries[1].size == 20);
    CHECK(entries[1].folder == 0);
    CHECK(entries[1].offset == 0);
    CHECK(entries[1].mode == 0100644);
    CHECK(entries[2].name == "docs/empty.txt");
    CHECK_FALSE(entries[2].directory);
    CHECK(entries[2].size == 0);
    CHECK_FALSE(entries[2].folder);
    CHECK(entries[3].name == "docs/café.txt");
    CHECK(entries[3].size == 11);
    CHECK(entries[3].offset == 20);

    CHECK(readAll(*reader, entries[1]) == "hello, stored world\n");
    CHECK(readAll(*reader, entries[3]) == "utf-8 name\n");
    CHECK(readAll(*reader, entries[0]).empty());
    CHECK(readAll(*reader, entries[2]).empty());

    // NOTE: anti entries describe deletions, so they never surface as entries.
    for (const auto& entry : entries) {
        CHECK(entry.name != "docs/gone.txt");
    }
}

TEST_CASE("7z reader decodes every supported codec") {
    std::string large(100'000, '-');
    for (std::size_t index = 0; index < large.size(); index += 41) {
        large[index] = static_cast<char>('A' + index % 23);
    }

    CodecKind codec = CodecKind::Copy;
    SUBCASE("Copy") {
        codec = CodecKind::Copy;
    }
    SUBCASE("LZMA1") {
        codec = CodecKind::Lzma1;
    }
    SUBCASE("LZMA2") {
        codec = CodecKind::Lzma2;
    }
    SUBCASE("Deflate") {
        codec = CodecKind::Deflate;
    }
    SUBCASE("BZip2") {
        codec = CodecKind::Bzip2;
    }

    SevenZipSpec spec;
    spec.codec = codec;
    spec.entries.push_back({.name = "large.txt", .data = large});
    spec.entries.push_back({.name = "small.txt", .data = "payload"});
    auto built = buildSevenZip(spec);

    TempFile temp(built.bytes);
    auto reader = openSevenZip(temp);
    REQUIRE(reader);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].size == large.size());
    CHECK(entries[0].folder == 0);
    CHECK(entries[0].offset == 0);
    CHECK(entries[1].offset == large.size());
    CHECK(readAll(*reader, entries[0]) == large);
    CHECK(readAll(*reader, entries[1]) == "payload");
    CHECK(streamText(*reader, entries[0], 2) == large);
}

TEST_CASE("7z reader decodes solid entries selectively from the block start") {
    SevenZipSpec spec;
    spec.entries.push_back({.name = "a.txt", .data = "first file contents"});
    spec.entries.push_back({.name = "b.txt", .data = "second file contents, a bit longer"});
    spec.entries.push_back({.name = "c.txt", .data = "third"});
    auto built = buildSevenZip(spec);

    auto readFresh = [&](std::size_t index) {
        TempFile temp(built.bytes);
        auto reader = openSevenZip(temp);
        REQUIRE(reader);
        return readAll(*reader, collect(*reader)[index]);
    };
    CHECK(readFresh(2) == "third");
    CHECK(readFresh(1) == "second file contents, a bit longer");
    CHECK(readFresh(0) == "first file contents");

    TempFile temp(built.bytes);
    auto reader = openSevenZip(temp);
    REQUIRE(reader);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 3);
    CHECK(entries[1].offset == entries[0].size);
    CHECK(entries[2].offset == entries[0].size + entries[1].size);
    CHECK(readAll(*reader, entries[0]) == "first file contents");
    CHECK(readAll(*reader, entries[1]) == "second file contents, a bit longer");
    CHECK(readAll(*reader, entries[2]) == "third");
}

TEST_CASE("7z reader refuses unsupported codecs without partial output") {
    SevenZipSpec base = mixedSpec();

    CodecKind codec = CodecKind::Ppmd;
    std::string_view expected = "7z codec PPMd (03-04-01) is not supported";
    SUBCASE("PPMd") {
        codec = CodecKind::Ppmd;
        expected = "7z codec PPMd (03-04-01) is not supported";
    }
    SUBCASE("BCJ filter chain") {
        codec = CodecKind::BcjLzma2;
        expected = "7z filter chains are not supported";
    }

    SevenZipSpec spec = base;
    spec.codec = codec;
    auto built = buildSevenZip(spec);

    TempFile temp(built.bytes);
    auto reader = openSevenZip(temp);
    REQUIRE(reader);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 4);
    CHECK(entries[1].name == "docs/readme.txt");

    std::array<std::byte, 64> scratch{};
    std::uint64_t delivered = 0;
    auto streamed = reader->streamEntry(entries[1], scratch, [&](std::span<const std::byte> chunk) {
        delivered += chunk.size();
        return Result<void>{};
    });
    REQUIRE_FALSE(streamed);
    CHECK(streamed.error().kind == ErrorKind::Unsupported);
    CHECK(streamed.error().what == expected);
    CHECK(delivered == 0);
}

TEST_CASE("7z reader reports password requirements without partial output") {
    SUBCASE("data encrypted") {
        SevenZipSpec spec = mixedSpec();
        spec.codec = CodecKind::AesLzma2;
        auto built = buildSevenZip(spec);

        TempFile temp(built.bytes);
        auto reader = openSevenZip(temp);
        REQUIRE(reader);
        auto entries = collect(*reader);
        REQUIRE(entries.size() == 4);

        std::array<std::byte, 64> scratch{};
        std::uint64_t delivered = 0;
        auto streamed =
            reader->streamEntry(entries[1], scratch, [&](std::span<const std::byte> chunk) {
                delivered += chunk.size();
                return Result<void>{};
            });
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::PasswordRequired);
        CHECK(streamed.error().what == "7z entry is encrypted");
        CHECK(delivered == 0);
    }
    SUBCASE("header encrypted") {
        SevenZipSpec spec = mixedSpec();
        spec.encryptHeader = true;
        auto built = buildSevenZip(spec);

        TempFile temp(built.bytes);
        auto reader = openSevenZip(temp);
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::PasswordRequired);
        CHECK(reader.error().what == "7z header is encrypted");
    }
}

TEST_CASE("7z reader handles plain headers and empty archives") {
    SevenZipSpec spec = mixedSpec();
    spec.compressHeader = false;
    auto built = buildSevenZip(spec);

    TempFile temp(built.bytes);
    auto reader = openSevenZip(temp);
    REQUIRE(reader);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 4);
    CHECK(readAll(*reader, entries[1]) == "hello, stored world\n");
    CHECK(readAll(*reader, entries[3]) == "utf-8 name\n");

    SevenZipSpec empty;
    auto emptyBuilt = buildSevenZip(empty);
    TempFile emptyTemp(emptyBuilt.bytes);
    auto emptyReader = openSevenZip(emptyTemp);
    REQUIRE(emptyReader);
    CHECK(emptyReader->entryCount() == 0);
    CHECK(collect(*emptyReader).empty());
}

TEST_CASE("7z reader rejects malformed archives") {
    auto built = buildSevenZip(mixedSpec());

    SUBCASE("bad magic") {
        auto broken = built.bytes;
        broken[0] = std::byte{'P'};
        checkRejected(broken, ErrorKind::Malformed, "not a 7z archive");
    }
    SUBCASE("bad version") {
        auto broken = built.bytes;
        broken[6] = std::byte{0x01};
        checkRejected(broken, ErrorKind::Unsupported, "unsupported 7z version");
    }
    SUBCASE("start header CRC mismatch") {
        auto broken = built.bytes;
        broken[8] = std::byte{0xFF};
        checkRejected(broken, ErrorKind::Integrity, "7z start header CRC mismatch");
    }
    SUBCASE("header past end of file") {
        auto broken = built.bytes;
        patch64(broken, 12, 0x00FFFFFF);
        std::span<const std::byte> start(broken.data() + 12, 20);
        patch32(broken, 8, Crc32::of(start));
        checkRejected(broken, ErrorKind::Truncated, "7z header extends past end of file");
    }
    SUBCASE("header CRC mismatch") {
        auto broken = built.bytes;
        std::size_t last = broken.size() - 1;
        broken[last] ^= std::byte{0xFF};
        checkRejected(broken, ErrorKind::Integrity, "7z header CRC mismatch");
    }
    SUBCASE("substream count does not match files") {
        SevenZipSpec spec = mixedSpec();
        spec.phantomSubstream = true;
        auto mismatched = buildSevenZip(spec);
        checkRejected(mismatched.bytes, ErrorKind::Malformed, "7z file streams do not match files");
    }
    SUBCASE("substream sizes exceed the folder") {
        SevenZipSpec plain;
        plain.compressHeader = false;
        plain.entries.push_back({.name = "a.txt", .data = "0123456789ABCDEF"});
        plain.entries.push_back({.name = "b.txt", .data = "0123456789ABCDEF"});
        auto plainBuilt = buildSevenZip(plain);
        REQUIRE(plainBuilt.subSizeOffsets.size() == 1);

        auto broken = plainBuilt;
        patchHeaderByte(broken, broken.subSizeOffsets[0], std::byte{0x7F});
        checkRejected(broken.bytes, ErrorKind::Malformed, "7z substream sizes exceed the folder");
    }
    SUBCASE("entry name is empty") {
        SevenZipSpec spec;
        spec.compressHeader = false;
        spec.entries.push_back({.name = "", .data = "x"});
        auto nameless = buildSevenZip(spec);
        checkRejected(nameless.bytes, ErrorKind::Malformed, "7z entry name is empty");
    }
    SUBCASE("unknown header tag") {
        SevenZipSpec plain = mixedSpec();
        plain.compressHeader = false;
        auto plainBuilt = buildSevenZip(plain);

        auto broken = plainBuilt;
        patchHeaderByte(broken, broken.headerStart, std::byte{0x42});
        checkRejected(broken.bytes, ErrorKind::Malformed, "7z header has no magic");
    }
}

TEST_CASE("7z reader verifies every checksum layer") {
    SUBCASE("pack CRC") {
        SevenZipSpec spec;
        spec.codec = CodecKind::Copy;
        spec.compressHeader = false;
        spec.entries.push_back({.name = "a.txt", .data = "checksum me"});
        auto built = buildSevenZip(spec);
        REQUIRE_FALSE(built.folderPackOffsets.empty());

        auto broken = built.bytes;
        broken[built.folderPackOffsets[0]] ^= std::byte{0xFF};
        TempFile temp(broken);
        auto reader = openSevenZip(temp);
        REQUIRE(reader);
        auto text = streamText(*reader, collect(*reader)[0]);
        REQUIRE_FALSE(text);
        CHECK(text.error().kind == ErrorKind::Integrity);
        CHECK(text.error().what == "7z pack CRC-32 mismatch");
    }
    SUBCASE("entry CRC") {
        SevenZipSpec spec;
        spec.compressHeader = false;
        spec.entries.push_back({.name = "a.txt", .data = "checksum me"});
        auto built = buildSevenZip(spec);
        REQUIRE(built.subCrcOffsets.size() == 1);

        auto broken = built;
        patchHeaderByte(
            broken,
            broken.subCrcOffsets[0],
            broken.bytes[broken.subCrcOffsets[0]] ^ std::byte{0xFF}
        );
        TempFile temp(broken.bytes);
        auto reader = openSevenZip(temp);
        REQUIRE(reader);
        auto text = streamText(*reader, collect(*reader)[0]);
        REQUIRE_FALSE(text);
        CHECK(text.error().kind == ErrorKind::Integrity);
        CHECK(text.error().what == "7z entry CRC-32 mismatch");
    }
    SUBCASE("folder CRC") {
        SevenZipSpec spec;
        spec.compressHeader = false;
        spec.entries.push_back({.name = "a.txt", .data = "checksum me"});
        auto built = buildSevenZip(spec);
        REQUIRE(built.folderCrcOffsets.size() == 1);

        auto broken = built;
        patchHeaderByte(
            broken,
            broken.folderCrcOffsets[0],
            broken.bytes[broken.folderCrcOffsets[0]] ^ std::byte{0xFF}
        );
        TempFile temp(broken.bytes);
        auto reader = openSevenZip(temp);
        REQUIRE(reader);
        auto text = streamText(*reader, collect(*reader)[0]);
        REQUIRE_FALSE(text);
        CHECK(text.error().kind == ErrorKind::Integrity);
        CHECK(text.error().what == "7z folder CRC-32 mismatch");
    }
}

TEST_CASE("7z reader enforces caller limits before decoding") {
    auto built = buildSevenZip(mixedSpec());
    checkRejected(
        built.bytes,
        ErrorKind::LimitExceeded,
        "7z entry count exceeds limit",
        {.maxEntries = 2}
    );
    checkRejected(
        built.bytes,
        ErrorKind::LimitExceeded,
        "7z header exceeds limit",
        {.maxHeaderBytes = 16}
    );

    SevenZipSpec split;
    split.solid = false;
    split.entries.push_back({.name = "a.txt", .data = "x"});
    split.entries.push_back({.name = "b.txt", .data = "y"});
    auto splitBuilt = buildSevenZip(split);
    checkRejected(
        splitBuilt.bytes,
        ErrorKind::LimitExceeded,
        "7z folder count exceeds limit",
        {.maxFolders = 1}
    );

    SevenZipSpec plain = mixedSpec();
    plain.compressHeader = false;
    auto plainBuilt = buildSevenZip(plain);

    TempFile temp(plainBuilt.bytes);
    auto reader = openSevenZip(temp, {.decoderMemLimitBytes = 1024});
    REQUIRE(reader);
    auto text = streamText(*reader, collect(*reader)[1]);
    REQUIRE_FALSE(text);
    CHECK(text.error().kind == ErrorKind::LimitExceeded);
    CHECK(text.error().what == "7z lzma dictionary exceeds decoder memory limit");

    TempFile small(built.bytes);
    auto limited = openSevenZip(small, {.maxEntryBytes = 4});
    REQUIRE(limited);
    auto entries = collect(*limited);
    auto tiny = streamText(*limited, entries[1]);
    REQUIRE_FALSE(tiny);
    CHECK(tiny.error().kind == ErrorKind::LimitExceeded);
    CHECK(tiny.error().what == "7z entry exceeds size limit");

    TempFile header(built.bytes);
    auto coded = openSevenZip(header, {.decoderMemLimitBytes = 1024});
    REQUIRE_FALSE(coded);
    CHECK(coded.error().kind == ErrorKind::LimitExceeded);
    CHECK(coded.error().what == "7z lzma dictionary exceeds decoder memory limit");
}

TEST_CASE("7z reader fails cleanly on every truncation and single-byte corruption") {
    auto built = buildSevenZip(mixedSpec());

    for (std::size_t length = 0; length < built.bytes.size(); ++length) {
        Bytes truncated(
            built.bytes.begin(),
            built.bytes.begin() + static_cast<std::ptrdiff_t>(length)
        );
        TempFile temp(truncated);
        auto file = temp.open();
        REQUIRE(file);
        auto reader = sevenzip::Reader::open(std::move(*file));
        if (!reader) {
            continue;
        }

        std::array<std::byte, 64> scratch{};
        for (const auto& entry : reader->entries()) {
            auto ignored = reader->streamEntry(entry, scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
            static_cast<void>(ignored);
        }
    }

    std::array<std::byte, 64> scratch{};
    for (std::size_t index = 0; index < built.bytes.size(); ++index) {
        auto corrupted = built.bytes;
        corrupted[index] ^= std::byte{0xA5};
        TempFile temp(corrupted);
        auto file = temp.open();
        REQUIRE(file);
        auto reader = sevenzip::Reader::open(std::move(*file));
        if (!reader) {
            continue;
        }

        for (const auto& entry : reader->entries()) {
            auto ignored = reader->streamEntry(entry, scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
            static_cast<void>(ignored);
        }
    }
}

TEST_CASE("looksLikeSevenZip detects the 7z magic") {
    auto built = buildSevenZip(mixedSpec());
    CHECK(sevenzip::looksLikeSevenZip(built.bytes));
    CHECK_FALSE(sevenzip::looksLikeSevenZip({}));
    CHECK_FALSE(sevenzip::looksLikeSevenZip(std::span(built.bytes).first(5)));

    std::array<std::byte, 6> noise{
        std::byte{'P'},
        std::byte{'K'},
        std::byte{3},
        std::byte{4},
        std::byte{0},
        std::byte{0},
    };
    CHECK_FALSE(sevenzip::looksLikeSevenZip(noise));

    auto detect = [&](std::span<const std::byte> bytes) {
        TempFile temp(Bytes(bytes.begin(), bytes.end()));
        auto file = temp.open();
        REQUIRE(file);
        auto format = detectFormat(*file);
        REQUIRE(format);
        return *format;
    };
    CHECK(detect(built.bytes) == ArchiveFormat{.container = Container::SevenZip});
    CHECK(name(ArchiveFormat{.container = Container::SevenZip}) == "7z");
    CHECK(detect(Bytes(built.bytes.begin(), built.bytes.begin() + 5)) == ArchiveFormat{});
}

TEST_CASE("7z reader decodes names, times and properties strictly") {
    SevenZipSpec spec;
    spec.entries.push_back({.name = "docs/日本語.txt", .data = "cjk\n"});
    spec.entries.push_back({.name = "docs/café.txt", .data = "latin\n"});
    spec.withComment = true;
    spec.withCTime = true;
    auto built = buildSevenZip(spec);

    TempFile temp(built.bytes);
    auto reader = openSevenZip(temp);
    REQUIRE(reader);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].name == "docs/日本語.txt");
    CHECK(entries[1].name == "docs/café.txt");
    CHECK(readAll(*reader, entries[0]) == "cjk\n");
    CHECK(readAll(*reader, entries[1]) == "latin\n");

    SevenZipSpec start;
    start.entries.push_back({.name = "a.txt", .data = "0123456789"});
    start.withStartPos = true;
    auto startBuilt = buildSevenZip(start);
    TempFile startTemp(startBuilt.bytes);
    auto startReader = openSevenZip(startTemp);
    REQUIRE(startReader);
    CHECK(readAll(*startReader, collect(*startReader)[0]) == "0123456789");

    SevenZipSpec bad = start;
    bad.badStartPos = true;
    auto badBuilt = buildSevenZip(bad);
    checkRejected(badBuilt.bytes, ErrorKind::Unsupported, "7z start positions are not supported");
}

TEST_CASE("7z reader replaces a lone surrogate with U+FFFD") {
    SevenZipSpec spec;
    spec.compressHeader = false;
    spec.entries.push_back({.name = "a.txt", .data = "x"});
    auto built = buildSevenZip(spec);
    REQUIRE(built.firstNameUnitOffset != 0);

    auto broken = built;
    patchHeaderByte(broken, broken.firstNameUnitOffset, std::byte{0x00});
    patchHeaderByte(broken, broken.firstNameUnitOffset + 1, std::byte{0xD8});
    TempFile temp(broken.bytes);
    auto reader = openSevenZip(temp);
    REQUIRE(reader);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].name == "\uFFFD.txt");
}
