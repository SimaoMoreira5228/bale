#include "formats/cpio/reader.hpp"

#include "formats/cpio/cpio_fixture.hpp"
#include "formats/detect.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::cpio;
using namespace bale::cpio::test;

namespace {

ErrorKind errorKind(const Listing& listing) {
    if (!listing.error) {
        FAIL("expected the archive to be rejected");
        return ErrorKind::Io;
    }
    return listing.error->kind;
}

std::vector<std::byte> golden(std::string_view name) {
    std::filesystem::path path = std::filesystem::path(FORMAT_GOLDEN_DIR) / "cpio" / "data" / name;
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

EntrySpec named(std::string name, std::string data = "") {
    EntrySpec spec;
    spec.name = std::move(name);
    spec.data = std::move(data);
    return spec;
}

EntrySpec directory(std::string name) {
    auto spec = named(std::move(name));
    spec.mode = 040755;
    return spec;
}

}

TEST_CASE("cpio reader lists the golden newc archive from GNU cpio 2.15") {
    // NOTE: tests/formats/cpio/data/newc.cpio was written by
    // `cpio -o -H newc` from GNU cpio 2.15 with mtimes fixed to 1583298367.
    auto reader = openBytes(golden("newc.cpio"));
    REQUIRE(reader);

    auto entries = std::vector<Entry>(reader->entries().begin(), reader->entries().end());
    REQUIRE(entries.size() == 9);

    CHECK(entries[0].name == "empty.txt");
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(entries[0].size == 0);
    CHECK(entries[1].name == "f1.txt");
    CHECK(entries[1].size == 9);
    CHECK(entries[2].name == "hard.txt");
    CHECK(entries[2].kind == EntryKind::HardLink);
    CHECK(entries[2].size == 0);
    CHECK(entries[2].linkTarget == "hard2.txt");
    CHECK(entries[3].name == "hard2.txt");
    CHECK(entries[3].kind == EntryKind::Regular);
    CHECK(entries[3].size == 12);
    CHECK(entries[4].name == "hello.txt");
    CHECK(entries[4].mode == 0100644);
    CHECK(entries[4].uid == 1000);
    CHECK(entries[4].gid == 1000);
    CHECK(entries[4].mtimeSeconds == 1583298367);
    CHECK(entries[5].name == "link.txt");
    CHECK(entries[5].kind == EntryKind::Symlink);
    CHECK(entries[5].mode == 0120777);
    CHECK(streamAll(*reader, entries[5]) == "hello.txt");
    CHECK(entries[6].name == "odd.bin");
    CHECK(entries[6].size == 17);
    CHECK(entries[7].name == "sub");
    CHECK(entries[7].kind == EntryKind::Directory);
    CHECK(entries[8].name == "sub/nested.txt");
    CHECK(streamAll(*reader, entries[8], 3) == "nested\n");
    CHECK(streamAll(*reader, entries[1]) == "trailtest");
    CHECK(streamAll(*reader, entries[3]) == "hardlinksrc\n");
}

TEST_CASE("cpio reader accepts the golden crc archive from GNU cpio 2.15") {
    // NOTE: tests/formats/cpio/data/crc.cpio was written by
    // `cpio -o -H crc` from GNU cpio 2.15; the check field is a plain
    // byte sum of regular file data, zero for symlinks and directories.
    auto reader = openBytes(golden("crc.cpio"));
    REQUIRE(reader);
    CHECK(reader->entryCount() == 9);

    std::vector<std::byte> scratch(64);
    auto discard = [](std::span<const std::byte>) -> Result<void> {
        return {};
    };
    for (const auto& entry : reader->entries()) {
        if (entry.kind != EntryKind::Regular && entry.kind != EntryKind::Symlink) {
            continue;
        }
        CHECK(reader->streamEntry(entry, scratch, discard));
    }

    auto corrupted = golden("crc.cpio");
    std::string_view needle = "hardlinksrc";
    auto found = std::search(
        corrupted.begin(),
        corrupted.end(),
        reinterpret_cast<const std::byte*>(needle.data()),
        reinterpret_cast<const std::byte*>(needle.data() + needle.size())
    );
    REQUIRE(found != corrupted.end());
    *found ^= std::byte{0xFF};

    auto broken = openBytes(corrupted);
    REQUIRE(broken);
    std::vector<std::string> failures;
    for (const auto& entry : broken->entries()) {
        if (entry.kind != EntryKind::Regular) {
            continue;
        }
        auto checked = broken->streamEntry(entry, scratch, discard);
        if (!checked) {
            failures.push_back(std::string(entry.name));
            CHECK(checked.error().kind == ErrorKind::Integrity);
            CHECK(checked.error().what == "cpio checksum mismatch");
        }
    }
    CHECK(failures == std::vector<std::string>{"hard2.txt"});
}

TEST_CASE("cpio reader maps hardlinks through inode identity") {
    auto first = named("first.txt", "shared");
    first.ino = 7;
    first.nlink = 2;

    auto link = named("second.txt");
    link.ino = 7;
    link.nlink = 2;

    ArchiveBuilder builder;
    builder.entry(first).entry(link).trailer();

    auto listing = listArchive(builder.bytes());
    REQUIRE_FALSE(listing.error.has_value());
    REQUIRE(listing.entries.size() == 2);
    CHECK(listing.entries[0].kind == EntryKind::Regular);
    CHECK(listing.entries[1].kind == EntryKind::HardLink);
    CHECK(listing.entries[1].linkTarget == "first.txt");

    ArchiveBuilder dangling;
    dangling.entry(link).trailer();
    auto alone = listArchive(dangling.bytes());
    REQUIRE_FALSE(alone.error.has_value());
    REQUIRE(alone.entries.size() == 1);
    CHECK(alone.entries[0].kind == EntryKind::Regular);

    auto lonely = named("lonely.txt");
    lonely.ino = 9;
    lonely.nlink = 1;
    ArchiveBuilder single;
    single.entry(lonely).trailer();
    auto only = listArchive(single.bytes());
    REQUIRE_FALSE(only.error.has_value());
    CHECK(only.entries[0].kind == EntryKind::Regular);

    auto directoryLink = directory("dir");
    directoryLink.ino = 11;
    directoryLink.nlink = 3;
    ArchiveBuilder nested;
    nested.entry(directoryLink).trailer();
    auto directories = listArchive(nested.bytes());
    REQUIRE_FALSE(directories.error.has_value());
    CHECK(directories.entries[0].kind == EntryKind::Directory);
}

TEST_CASE("cpio reader lists device nodes and sockets without data") {
    auto character = named("null");
    character.mode = 0020666;
    character.ino = 1;

    auto block = named("disk");
    block.mode = 0060600;
    block.ino = 2;

    auto fifo = named("pipe");
    fifo.mode = 0010644;

    auto socket = named("sock");
    socket.mode = 0140755;

    auto unknown = named("weird");
    unknown.mode = 0030644;

    ArchiveBuilder builder;
    builder.entry(character).entry(block).entry(fifo).entry(socket).entry(unknown).trailer();

    auto listing = listArchive(builder.bytes());
    REQUIRE_FALSE(listing.error.has_value());
    REQUIRE(listing.entries.size() == 5);
    CHECK(listing.entries[0].kind == EntryKind::CharDevice);
    CHECK(listing.entries[1].kind == EntryKind::BlockDevice);
    CHECK(listing.entries[2].kind == EntryKind::Fifo);
    CHECK(listing.entries[3].kind == EntryKind::Socket);
    CHECK(listing.entries[4].kind == EntryKind::Other);
}

TEST_CASE("cpio reader rejects malformed archives") {
    auto bad = [](const ArchiveBuilder& builder) {
        return errorKind(listArchive(builder.bytes()));
    };

    ArchiveBuilder empty;
    empty.truncate(0);
    CHECK(bad(empty) == ErrorKind::Malformed);

    ArchiveBuilder shortMagic;
    shortMagic.truncate(3);
    CHECK(bad(shortMagic) == ErrorKind::Malformed);

    ArchiveBuilder odcMagic;
    odcMagic.raw("070707").raw(std::string(200, '\0'));
    CHECK(bad(odcMagic) == ErrorKind::Malformed);

    auto hex = named("a.txt", "x");
    hex.magic = "07070x";
    ArchiveBuilder badHex;
    badHex.entry(hex).trailer();
    CHECK(bad(badHex) == ErrorKind::Malformed);

    ArchiveBuilder noTrailer;
    noTrailer.entry(named("a.txt", "x"));
    CHECK(bad(noTrailer) == ErrorKind::Truncated);

    ArchiveBuilder trailerData;
    trailerData.entry(named("a.txt", "x"));
    EntrySpec trailer;
    trailer.name = "TRAILER!!!";
    trailer.data = "x";
    trailerData.entry(trailer);
    CHECK(bad(trailerData) == ErrorKind::Malformed);

    ArchiveBuilder garbage;
    garbage.entry(named("a.txt", "x")).trailer().raw("junk");
    CHECK(bad(garbage) == ErrorKind::Malformed);

    ArchiveBuilder padded;
    padded.entry(named("a.txt", "x")).trailer().raw(std::string(500, '\0'));
    CHECK_FALSE(listArchive(padded.bytes()).error.has_value());

    auto nameless = named("", "x");
    ArchiveBuilder emptyName;
    emptyName.entry(nameless).trailer();
    CHECK(bad(emptyName) == ErrorKind::Malformed);

    auto directoryData = directory("dir");
    directoryData.data = "x";
    ArchiveBuilder directoryPayload;
    directoryPayload.entry(directoryData).trailer();
    CHECK(bad(directoryPayload) == ErrorKind::Malformed);
}

TEST_CASE("cpio reader reports truncation at every boundary") {
    ArchiveBuilder builder;
    builder.entry(named("a.txt", "payload")).entry(named("bb", "x")).trailer();

    const auto& full = builder.bytes();
    for (std::size_t cut = 0; cut < full.size(); ++cut) {
        CAPTURE(cut);
        auto prefix =
            std::vector<std::byte>(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut));
        if (cut < newcMagic.size()) {
            CHECK(errorKind(listArchive(prefix)) == ErrorKind::Malformed);
        } else {
            CHECK(errorKind(listArchive(prefix)) == ErrorKind::Truncated);
        }
    }
}

TEST_CASE("cpio reader enforces caller limits before allocating") {
    ArchiveBuilder builder;
    builder.entry(named("a.txt", "data")).entry(named("b.txt", "data")).trailer();

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
}

TEST_CASE("looksLikeCpio detects newc headers and refuses odc and binary headers") {
    CHECK(looksLikeCpio(
        std::array<std::byte, 6>{
            std::byte{'0'},
            std::byte{'7'},
            std::byte{'0'},
            std::byte{'7'},
            std::byte{'0'},
            std::byte{'1'},
        }
    ));
    CHECK(looksLikeCpio(
        std::array<std::byte, 6>{
            std::byte{'0'},
            std::byte{'7'},
            std::byte{'0'},
            std::byte{'7'},
            std::byte{'0'},
            std::byte{'2'},
        }
    ));
    CHECK_FALSE(looksLikeCpio(
        std::array<std::byte, 3>{
            std::byte{'0'},
            std::byte{'7'},
            std::byte{'0'},
        }
    ));

    std::array<std::byte, 6> odc{
        std::byte{'0'},
        std::byte{'7'},
        std::byte{'0'},
        std::byte{'7'},
        std::byte{'0'},
        std::byte{'7'},
    };
    CHECK_FALSE(looksLikeCpio(odc));

    std::array<std::byte, 2> binary{
        std::byte{0x71},
        std::byte{0xC7},
    };
    CHECK_FALSE(looksLikeCpio(binary));

    bale::test::TempFile archive(golden("newc.cpio"));
    auto file = archive.open();
    REQUIRE(file);
    auto format = detectFormat(*file);
    REQUIRE(format);
    CHECK(*format == ArchiveFormat{.container = Container::Cpio});
    CHECK(name(*format) == "cpio");
}
