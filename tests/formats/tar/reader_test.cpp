#include "formats/tar/reader.hpp"

#include "formats/tar/tar_fixture.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::tar;
using namespace bale::tar::test;

namespace {

HeaderSpec named(std::string name, char typeflag = '0') {
    HeaderSpec spec;
    spec.name = std::move(name);
    spec.typeflag = typeflag;
    return spec;
}

std::vector<std::byte> prefix(const std::vector<std::byte>& bytes, std::size_t length) {
    return {bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length)};
}

ErrorKind errorKind(const Listing& listing) {
    if (!listing.error) {
        FAIL("expected the archive to be rejected");
        return ErrorKind::Io;
    }
    return listing.error->kind;
}

}

TEST_CASE("Reader lists every basic entry kind with data offsets") {
    auto file = named("file.txt");
    file.prefix = "some/deep/dir";

    auto hardLink = named("hard", '1');
    hardLink.linkName = "some/deep/dir/file.txt";
    hardLink.size = 100;

    auto symlink = named("sym", '2');
    symlink.linkName = "../target";

    ArchiveBuilder builder;
    builder.entry(file, "hello world")
        .entry(named("nul-type", '\0'), "x")
        .entry(named("contiguous", '7'), std::string(600, 'c'))
        .entry(named("dir/", '5'), "")
        .block(makeHeader(hardLink))
        .block(makeHeader(symlink))
        .block(makeHeader(named("chr", '3')))
        .block(makeHeader(named("fifo", '6')))
        .entry(named("vendor", 'Q'), "12345")
        .zeros(2);

    auto listing = listArchive(builder.bytes());
    REQUIRE_FALSE(listing.error.has_value());
    REQUIRE(listing.entries.size() == 9);

    const auto& entries = listing.entries;
    CHECK(entries[0].path == "some/deep/dir/file.txt");
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(entries[0].dataOffset == 512);
    CHECK(entries[0].size == 11);
    CHECK(entries[1].kind == EntryKind::Regular);
    CHECK(entries[1].dataOffset == 3 * 512);
    CHECK(entries[2].kind == EntryKind::Regular);
    CHECK(entries[2].size == 600);
    CHECK(entries[3].kind == EntryKind::Directory);
    CHECK(entries[3].path == "dir/");
    CHECK(entries[4].kind == EntryKind::HardLink);
    CHECK(entries[4].linkTarget == "some/deep/dir/file.txt");
    CHECK(entries[4].size == 0);
    CHECK(entries[5].kind == EntryKind::Symlink);
    CHECK(entries[5].linkTarget == "../target");
    CHECK(entries[6].kind == EntryKind::CharDevice);
    CHECK(entries[7].kind == EntryKind::Fifo);
    CHECK(entries[8].kind == EntryKind::Other);
    CHECK(entries[8].size == 5);

    std::string content(entries[0].size, '\0');
    for (std::size_t index = 0; index < content.size(); ++index) {
        content[index] = static_cast<char>(builder.bytes()[entries[0].dataOffset + index]);
    }
    CHECK(content == "hello world");
}

TEST_CASE("Reader reuses one entry and keeps returning end after the archive") {
    ArchiveBuilder builder;
    builder.entry(named(std::string(100, 'a')), "1").entry(named("b"), "2").zeros(2);

    bale::test::TempFile archive(builder.bytes());
    auto file = archive.open();
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);

    auto first = reader->next();
    REQUIRE(first);
    REQUIRE(*first != nullptr);
    CHECK((*first)->path == std::string(100, 'a'));
    CHECK((*first)->uname == "user");
    CHECK((*first)->headerOffset == 0);

    auto second = reader->next();
    REQUIRE(second);
    CHECK(*second == *first);
    CHECK((*second)->path == "b");
    CHECK((*second)->headerOffset == 1024);

    CHECK(reader->next() == nullptr);
    CHECK(reader->next() == nullptr);
}

TEST_CASE("Reader applies pax per-entry and global overrides") {
    auto global = paxRecord("uid", "1000") + paxRecord("uname", "builder");
    auto longPath = "pax/" + std::string(200, 'p');
    auto local = paxRecord("path", longPath) + paxRecord("size", "3") +
        paxRecord("mtime", "1700000000.5") + paxRecord("linkpath", "ignored-for-regular");

    auto lying = named("short-name");
    lying.size = 99999;
    lying.mtime = 42;

    auto plain = named("plain");
    plain.mtime = 77;
    plain.uid = 5;

    ArchiveBuilder builder;
    builder.meta('g', global).meta('x', local).block(makeHeader(lying)).data("abc");
    builder.entry(plain, "zz").meta('g', paxRecord("uid", "")).entry(plain, "").zeros(2);

    bale::test::TempFile archive(builder.bytes());
    auto file = archive.open();
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);

    auto entry = reader->next();
    REQUIRE(entry);
    REQUIRE(*entry != nullptr);
    CHECK((*entry)->path == longPath);
    CHECK((*entry)->size == 3);
    CHECK((*entry)->dataOffset == 5 * 512);
    CHECK((*entry)->mtimeSeconds == 1700000000);
    CHECK((*entry)->mtimeNanoseconds == 500'000'000);
    CHECK((*entry)->uid == 1000);
    CHECK((*entry)->uname == "builder");

    entry = reader->next();
    REQUIRE(entry);
    REQUIRE(*entry != nullptr);
    CHECK((*entry)->path == "plain");
    CHECK((*entry)->dataOffset == 7 * 512);
    CHECK((*entry)->mtimeSeconds == 77);
    CHECK((*entry)->mtimeNanoseconds == 0);
    CHECK((*entry)->uid == 1000);

    entry = reader->next();
    REQUIRE(entry);
    REQUIRE(*entry != nullptr);
    CHECK((*entry)->uid == 5);
    CHECK((*entry)->uname == "builder");

    CHECK(reader->next() == nullptr);
}

TEST_CASE("Reader reads GNU long names and base-256 sizes") {
    auto longName = "gnu/" + std::string(300, 'n');
    auto longLink = "link/" + std::string(200, 'k');

    auto symlink = named(longName.substr(0, 100), '2');
    symlink.magic = gnuMagic;
    symlink.linkName = longLink.substr(0, 100);

    auto big = named("big.bin");
    big.magic = gnuMagic;
    big.base256Size = true;
    big.size = 1000;

    ArchiveBuilder builder;
    builder.meta('L', longName + '\0').meta('K', longLink + '\0').block(makeHeader(symlink));
    builder.block(makeHeader(big)).data(std::string(1000, 'b')).zeros(2);

    auto listing = listArchive(builder.bytes());
    REQUIRE_FALSE(listing.error.has_value());
    REQUIRE(listing.entries.size() == 2);
    CHECK(listing.entries[0].path == longName);
    CHECK(listing.entries[0].linkTarget == longLink);
    CHECK(listing.entries[0].kind == EntryKind::Symlink);
    CHECK(listing.entries[1].path == "big.bin");
    CHECK(listing.entries[1].size == 1000);
    CHECK(listing.entries[1].dataOffset == 6 * 512);
}

TEST_CASE("Reader reports truncation at every structure boundary") {
    ArchiveBuilder builder;
    builder.entry(named("a"), std::string(700, 'a'));
    const auto& full = builder.bytes();

    for (std::size_t cut : {100UL, 511UL, 512UL, 1000UL, 1211UL, 1212UL, 1535UL}) {
        CAPTURE(cut);
        CHECK(errorKind(listArchive(prefix(full, cut))) == ErrorKind::Truncated);
    }

    ArchiveBuilder tail;
    tail.entry(named("a"), std::string(700, 'a')).raw(100, std::byte{0});
    CHECK(errorKind(listArchive(tail.bytes())) == ErrorKind::Truncated);

    ArchiveBuilder pax;
    pax.meta('x', paxRecord("path", std::string(80, 'p'))).entry(named("a"), "");
    CHECK(errorKind(listArchive(prefix(pax.bytes(), 512 + 50))) == ErrorKind::Truncated);
}

TEST_CASE("Reader rejects sizes that overflow or exceed the file") {
    auto huge = named("huge");
    huge.base256Size = true;
    huge.size = UINT64_MAX - 10;

    ArchiveBuilder overflow;
    overflow.block(makeHeader(huge)).zeros(2);
    CHECK(errorKind(listArchive(overflow.bytes())) == ErrorKind::Malformed);

    huge.size = std::uint64_t{1} << 62;
    ArchiveBuilder beyond;
    beyond.block(makeHeader(huge)).zeros(2);
    CHECK(errorKind(listArchive(beyond.bytes())) == ErrorKind::Truncated);

    ArchiveBuilder paxSize;
    paxSize.meta('x', paxRecord("size", "18446744073709551615")).entry(named("a"), "").zeros(2);
    CHECK(errorKind(listArchive(paxSize.bytes())) == ErrorKind::Malformed);

    ArchiveBuilder wrongLength;
    wrongLength.meta('x', "30 path=short\n").entry(named("a"), "").zeros(2);
    auto listing = listArchive(wrongLength.bytes());
    CHECK(errorKind(listing) == ErrorKind::Malformed);
    CHECK((listing.error && listing.error->offset == 512));
}

TEST_CASE("Reader enforces caller limits before allocating") {
    auto declared = named("PaxHeader", 'x');
    declared.size = std::uint64_t{2} << 20;
    ArchiveBuilder oversized;
    oversized.block(makeHeader(declared)).zeros(2);
    CHECK(errorKind(listArchive(oversized.bytes())) == ErrorKind::LimitExceeded);

    Limits small;
    small.maxExtendedHeaderBytes = 128;
    small.maxPathBytes = 50;
    small.maxEntries = 2;

    ArchiveBuilder longPax;
    longPax.meta('x', paxRecord("path", std::string(60, 'p'))).entry(named("a"), "");
    CHECK(errorKind(listArchive(longPax.bytes(), small)) == ErrorKind::LimitExceeded);

    ArchiveBuilder longName;
    longName.meta('L', std::string(51, 'n') + '\0').entry(named("a"), "");
    CHECK(errorKind(listArchive(longName.bytes(), small)) == ErrorKind::LimitExceeded);

    auto joined = named(std::string(30, 'n'));
    joined.prefix = std::string(30, 'p');
    ArchiveBuilder ustarJoin;
    ustarJoin.block(makeHeader(joined)).zeros(2);
    CHECK(errorKind(listArchive(ustarJoin.bytes(), small)) == ErrorKind::LimitExceeded);

    ArchiveBuilder many;
    many.entry(named("1"), "").entry(named("2"), "").entry(named("3"), "").zeros(2);
    auto listing = listArchive(many.bytes(), small);
    CHECK(listing.entries.size() == 2);
    CHECK(errorKind(listing) == ErrorKind::LimitExceeded);
}

TEST_CASE("Reader refuses GNU sparse entries") {
    ArchiveBuilder sparse;
    sparse.entry(named("sparse", 'S'), "data").zeros(2);
    CHECK(errorKind(listArchive(sparse.bytes())) == ErrorKind::Unsupported);

    ArchiveBuilder paxSparse;
    paxSparse.meta('x', paxRecord("GNU.sparse.size", "100")).entry(named("a"), "").zeros(2);
    CHECK(errorKind(listArchive(paxSparse.bytes())) == ErrorKind::Unsupported);
}

TEST_CASE("Reader end-of-archive variants") {
    auto entryThen = [](auto&& finish) {
        ArchiveBuilder builder;
        builder.entry(named("a"), "data");
        finish(builder);
        return listArchive(builder.bytes());
    };

    auto twoZeros = entryThen([](ArchiveBuilder& builder) {
        builder.zeros(2).raw(1000, std::byte{0x5A});
    });
    CHECK_FALSE(twoZeros.error.has_value());
    CHECK(twoZeros.entries.size() == 1);

    auto oneZero = entryThen([](ArchiveBuilder& builder) {
        builder.zeros(1);
    });
    CHECK_FALSE(oneZero.error.has_value());
    CHECK(oneZero.entries.size() == 1);

    auto noZeros = entryThen([](ArchiveBuilder&) {
    });
    CHECK_FALSE(noZeros.error.has_value());
    CHECK(noZeros.entries.size() == 1);

    auto loneZero = entryThen([](ArchiveBuilder& builder) {
        builder.zeros(1).entry(named("hidden"), "");
    });
    CHECK(errorKind(loneZero) == ErrorKind::Malformed);
    CHECK(loneZero.entries.size() == 1);

    auto partialAfterZero = entryThen([](ArchiveBuilder& builder) {
        builder.zeros(1).raw(100, std::byte{0});
    });
    CHECK(errorKind(partialAfterZero) == ErrorKind::Truncated);

    auto danglingPax = entryThen([](ArchiveBuilder& builder) {
        builder.meta('x', paxRecord("path", "orphan")).zeros(2);
    });
    CHECK(errorKind(danglingPax) == ErrorKind::Malformed);

    auto danglingLongName = entryThen([](ArchiveBuilder& builder) {
        builder.meta('L', "orphan");
    });
    CHECK(errorKind(danglingLongName) == ErrorKind::Malformed);

    auto trailingGlobal = entryThen([](ArchiveBuilder& builder) {
        builder.meta('g', paxRecord("uid", "1")).zeros(2);
    });
    CHECK_FALSE(trailingGlobal.error.has_value());

    auto empty = listArchive({});
    CHECK_FALSE(empty.error.has_value());
    CHECK(empty.entries.empty());
}
