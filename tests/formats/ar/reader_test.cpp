#include "formats/ar/reader.hpp"

#include "formats/ar/ar_fixture.hpp"
#include "formats/detect.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::ar;
using namespace bale::ar::test;

namespace {

ErrorKind errorKind(const Listing& listing) {
    if (!listing.error) {
        FAIL("expected the archive to be rejected");
        return ErrorKind::Io;
    }
    return listing.error->kind;
}

std::vector<std::byte> golden(std::string_view name) {
    std::filesystem::path path = std::filesystem::path(FORMAT_GOLDEN_DIR) / "ar" / "data" / name;
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);

    std::vector<std::byte> bytes;
    char chunk[4096];
    while (file) {
        file.read(chunk, sizeof(chunk));
        auto count = file.gcount();
        for (std::streamsize index = 0; index < count; ++index) {
            bytes.push_back(static_cast<std::byte>(chunk[index]));
        }
    }
    return bytes;
}

Result<Reader> openBytes(std::span<const std::byte> bytes, const Limits& limits = {}) {
    bale::test::TempFile archive(bytes);
    REQUIRE(archive.ok());
    auto file = archive.open();
    REQUIRE(file);
    return Reader::open(std::move(*file), limits);
}

std::string streamAll(Reader& reader, const Entry& entry, std::size_t scratchSize = 256) {
    std::vector<std::byte> scratch(scratchSize);
    std::string text;
    auto streamed = reader.streamEntry(entry, scratch, [&](std::span<const std::byte> chunk) {
        text.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    REQUIRE(streamed);
    return text;
}

MemberSpec named(std::string name, std::string data = "") {
    MemberSpec spec;
    spec.nameField = std::move(name);
    spec.data = std::move(data);
    return spec;
}

}

TEST_CASE("ar reader lists golden System V archives from GNU ar 2.46.1") {
    // NOTE: tests/formats/ar/data/gnu.a and sysv.a were written by
    // `ar rcsD` from GNU binutils 2.46.1, which forces uid/gid/mtime to zero
    // and drops the file-type bits from the mode.
    auto reader = openBytes(golden("gnu.a"));
    REQUIRE(reader);

    auto entries = std::vector<Entry>(reader->entries().begin(), reader->entries().end());
    REQUIRE(entries.size() == 3);
    CHECK(entries[0].name == "hello.txt");
    CHECK(entries[0].size == 9);
    CHECK(entries[0].mode == 0644);
    CHECK(entries[0].uid == 0);
    CHECK(entries[0].gid == 0);
    CHECK(entries[0].mtimeSeconds == 0);
    CHECK(entries[1].name == "odd.txt");
    CHECK(entries[1].size == 29);
    CHECK(entries[2].name == "tiny.txt");
    CHECK(entries[2].size == 1);
    CHECK(streamAll(*reader, entries[0]) == "hello ar\n");
    CHECK(streamAll(*reader, entries[2]) == "x");

    auto symbols = openBytes(golden("sysv.a"));
    REQUIRE(symbols);
    auto indexed = std::vector<Entry>(symbols->entries().begin(), symbols->entries().end());
    REQUIRE(indexed.size() == 2);
    CHECK(indexed[0].name == "ans.o");
    CHECK(indexed[0].size == 1240);
    CHECK(indexed[1].name == "hello.txt");
    CHECK(streamAll(*symbols, indexed[1]) == "hello ar\n");
}

TEST_CASE("ar reader resolves golden GNU long names from GNU ar 2.46.1") {
    auto reader = openBytes(golden("long.a"));
    REQUIRE(reader);

    auto entries = std::vector<Entry>(reader->entries().begin(), reader->entries().end());
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].name == "a_very_long_filename_that_needs_the_gnu_string_table_001.txt");
    CHECK(entries[0].size == 18);
    CHECK(streamAll(*reader, entries[0]) == "long content here\n");
    CHECK(entries[1].name == "hello.txt");
}

TEST_CASE("ar reader resolves BSD extended names and skips BSD symbol tables") {
    // NOTE: tests/formats/ar/data/bsd.a is hand-built to the BSD #1/ layout
    // because GNU ar cannot emit it; fields mirror `ar rcsD` (uid/gid 1000,
    // mtime 1583298367, mode 100644).
    auto reader = openBytes(golden("bsd.a"));
    REQUIRE(reader);

    auto entries = std::vector<Entry>(reader->entries().begin(), reader->entries().end());
    REQUIRE(entries.size() == 3);
    CHECK(entries[0].name == "short.o");
    CHECK(entries[0].size == 6);
    CHECK(entries[0].mode == 0100644);
    CHECK(entries[0].uid == 1000);
    CHECK(entries[0].gid == 1000);
    CHECK(entries[0].mtimeSeconds == 1583298367);
    CHECK(entries[1].name == "this-is-a-long-bsd-name.o");
    CHECK(entries[1].size == 9);
    CHECK(streamAll(*reader, entries[0]) == "short\n");
    CHECK(streamAll(*reader, entries[1]) == "bsd long\n");
    CHECK(entries[2].name == "odd.o");
    CHECK(entries[2].size == 5);
    CHECK(streamAll(*reader, entries[2]) == "12345");
}

TEST_CASE("ar reader resolves GNU table references and skips symbol tables") {
    ArchiveBuilder builder;
    auto second = named("/11", "second!");
    second.date = "1583298367";
    second.uid = "1";
    second.gid = "2";
    second.mode = "100640";
    builder.member(named("//", "first.txt/\nsecond.txt/\n"))
        .member(named("/", "symbol index"))
        .member(named("/SYM64/", "64-bit index"))
        .member(named("SYMDEF", "bsd index"))
        .member(named("/0", "first"))
        .member(second);

    auto listing = listArchive(builder.bytes());
    REQUIRE_FALSE(listing.error.has_value());
    REQUIRE(listing.entries.size() == 2);
    CHECK(listing.entries[0].name == "first.txt");
    CHECK(listing.entries[0].size == 5);
    CHECK(listing.entries[0].dataOffset == 366);
    CHECK(listing.entries[1].name == "second.txt");
    CHECK(listing.entries[1].size == 7);
}

TEST_CASE("ar reader rejects malformed archives") {
    auto bad = [](const ArchiveBuilder& builder) {
        return errorKind(listArchive(builder.bytes()));
    };

    ArchiveBuilder empty;
    empty.truncate(0);
    CHECK(bad(empty) == ErrorKind::Malformed);

    ArchiveBuilder shortMagic;
    shortMagic.truncate(4);
    CHECK(bad(shortMagic) == ErrorKind::Malformed);

    ArchiveBuilder wrongMagic;
    wrongMagic.raw("!<arch?\n").member(named("a/", "x"));
    CHECK(bad(wrongMagic) == ErrorKind::Malformed);

    auto terminator = MemberSpec(named("a/", "x"));
    terminator.terminator = "!!";
    ArchiveBuilder badTerminator;
    badTerminator.member(terminator);
    CHECK(bad(badTerminator) == ErrorKind::Malformed);

    auto decimal = MemberSpec(named("a/", "x"));
    decimal.size = "12x";
    ArchiveBuilder badSize;
    badSize.member(decimal);
    CHECK(bad(badSize) == ErrorKind::Malformed);

    auto octal = MemberSpec(named("a/", "x"));
    octal.mode = "100648";
    ArchiveBuilder badMode;
    badMode.member(octal);
    CHECK(bad(badMode) == ErrorKind::Malformed);

    ArchiveBuilder nameless;
    nameless.member(named("                ", "x"));
    CHECK(bad(nameless) == ErrorKind::Malformed);

    ArchiveBuilder danglingRef;
    danglingRef.member(named("/0", "x"));
    CHECK(bad(danglingRef) == ErrorKind::Malformed);

    ArchiveBuilder tableOnly;
    tableOnly.member(named("//", "a.txt/\n"));
    CHECK(listArchive(tableOnly.bytes()).entries.empty());

    ArchiveBuilder tableOverflow;
    tableOverflow.member(named("//", "a.txt/\n")).member(named("/99", "x"));
    CHECK(bad(tableOverflow) == ErrorKind::Malformed);

    ArchiveBuilder unterminated;
    unterminated.member(named("//", "no-slash-here")).member(named("/0", "x"));
    CHECK(bad(unterminated) == ErrorKind::Malformed);

    ArchiveBuilder duplicateTable;
    duplicateTable.member(named("//", "a/\n")).member(named("//", "b/\n"));
    CHECK(bad(duplicateTable) == ErrorKind::Malformed);

    ArchiveBuilder emptyBsd;
    emptyBsd.member(named("#1/0", "x"));
    CHECK(bad(emptyBsd) == ErrorKind::Malformed);

    ArchiveBuilder bsdOverflow;
    bsdOverflow.member(named("#1/99", "x"));
    CHECK(bad(bsdOverflow) == ErrorKind::Malformed);

    ArchiveBuilder hashForm;
    hashForm.member(named("#2/99", "x"));
    CHECK(bad(hashForm) == ErrorKind::Unsupported);

    ArchiveBuilder slashForm;
    slashForm.member(named("/SYM", "x"));
    CHECK(bad(slashForm) == ErrorKind::Unsupported);
}

TEST_CASE("ar reader reports truncation at every boundary") {
    ArchiveBuilder builder;
    builder.member(named("a/", "payload")).member(named("b/", "x"));

    const auto& full = builder.bytes();
    for (std::size_t cut = 0; cut < full.size(); ++cut) {
        CAPTURE(cut);
        auto prefix =
            std::vector<std::byte>(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut));
        auto listing = listArchive(prefix);
        if (cut < magic.size()) {
            CHECK(errorKind(listing) == ErrorKind::Malformed);
        } else if (cut == magic.size() || cut == 76) {
            REQUIRE_FALSE(listing.error.has_value());
            CHECK(listing.entries.size() == (cut == magic.size() ? 0 : 1));
        } else {
            CHECK(errorKind(listing) == ErrorKind::Truncated);
        }
    }

    ArchiveBuilder missingPad;
    missingPad.member(named("odd/", "123"));
    auto truncated = missingPad.bytes();
    truncated.pop_back();
    CHECK(errorKind(listArchive(truncated)) == ErrorKind::Truncated);

    Limits unbounded;
    unbounded.maxEntryBytes = 0xFFFFFFFFFFFFFFFFULL;
    unbounded.maxTotalBytes = 0xFFFFFFFFFFFFFFFFULL;

    auto overflow = MemberSpec(named("huge/", ""));
    overflow.size = "9999999999";
    ArchiveBuilder hugeSize;
    hugeSize.member(overflow);
    CHECK(errorKind(listArchive(hugeSize.bytes(), unbounded)) == ErrorKind::Truncated);
}

TEST_CASE("ar reader enforces caller limits before allocating") {
    ArchiveBuilder builder;
    builder.member(named("aaa/", "data")).member(named("b/", "data"));

    Limits entries;
    entries.maxEntries = 1;
    auto listing = listArchive(builder.bytes(), entries);
    CHECK(listing.entries.empty());
    CHECK(errorKind(listing) == ErrorKind::LimitExceeded);

    Limits names;
    names.maxNameBytes = 2;
    CHECK(errorKind(listArchive(builder.bytes(), names)) == ErrorKind::LimitExceeded);

    Limits sizes;
    sizes.maxEntryBytes = 3;
    CHECK(errorKind(listArchive(builder.bytes(), sizes)) == ErrorKind::LimitExceeded);

    Limits total;
    total.maxTotalBytes = 5;
    CHECK(errorKind(listArchive(builder.bytes(), total)) == ErrorKind::LimitExceeded);

    ArchiveBuilder table;
    table.member(named("//", std::string(64, 'a')));
    Limits tables;
    tables.maxStringTableBytes = 16;
    CHECK(errorKind(listArchive(table.bytes(), tables)) == ErrorKind::LimitExceeded);
}

TEST_CASE("ar reader streams data in bounded chunks") {
    ArchiveBuilder builder;
    builder.member(named("a/", std::string(10'000, 'z')));

    auto reader = openBytes(builder.bytes());
    REQUIRE(reader);
    auto entries = std::vector<Entry>(reader->entries().begin(), reader->entries().end());
    REQUIRE(entries.size() == 1);
    CHECK(streamAll(*reader, entries[0], 7) == std::string(10'000, 'z'));
}

TEST_CASE("looksLikeAr detects the ar magic") {
    CHECK(looksLikeAr(
        std::array<std::byte, 8>{
            std::byte{'!'},
            std::byte{'<'},
            std::byte{'a'},
            std::byte{'r'},
            std::byte{'c'},
            std::byte{'h'},
            std::byte{'>'},
            std::byte{'\n'},
        }
    ));
    CHECK_FALSE(looksLikeAr(
        std::array<std::byte, 3>{
            std::byte{'!'},
            std::byte{'<'},
            std::byte{'a'},
        }
    ));
    CHECK_FALSE(looksLikeAr(
        std::array<std::byte, 8>{
            std::byte{'0'},
            std::byte{'7'},
            std::byte{'0'},
            std::byte{'7'},
            std::byte{'0'},
            std::byte{'1'},
            std::byte{0},
            std::byte{0},
        }
    ));

    bale::test::TempFile archive(golden("gnu.a"));
    auto file = archive.open();
    REQUIRE(file);
    auto format = detectFormat(*file);
    REQUIRE(format);
    CHECK(*format == ArchiveFormat{.container = Container::Ar});
    CHECK(name(*format) == "ar");
}
