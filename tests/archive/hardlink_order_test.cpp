#include "archive/reader.hpp"
#include "archive/writer.hpp"

#include "archive/archive_fixture.hpp"
#include "extract/extractor.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <filesystem>
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
using bale::test::TempPath;

namespace {

ArchivePath at(std::string_view path) {
    std::uint32_t depth = 1;
    for (char value : path) {
        if (value == '/') {
            ++depth;
        }
    }
    return ArchivePath{.path = path, .depth = depth};
}

void buildPair(const std::filesystem::path& path, bool linkFirst) {
    auto writer = newWriter(path);
    if (linkFirst) {
        REQUIRE(writer.addHardLink("a", "z"));
        REQUIRE(writer.addBytes("z", bytesOf("data"), {.mtimeNanoseconds = 7, .mode = 0600}));
    } else {
        REQUIRE(writer.addBytes("z", bytesOf("data"), {.mtimeNanoseconds = 7, .mode = 0600}));
        REQUIRE(writer.addHardLink("a", "z"));
    }
    REQUIRE(writer.finish());
}

} // namespace

TEST_CASE("native hardlinks land identically regardless of insertion order") {
    TempPath forwardTemp;
    TempPath reversedTemp;
    buildPair(forwardTemp.path(), false);
    buildPair(reversedTemp.path(), true);
    CHECK(readAll(forwardTemp.path()) == readAll(reversedTemp.path()));

    auto file = File::openRead(reversedTemp.path());
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    const auto& entries = reader->manifest().entries;
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].path == "a");
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(entries[0].mode == 0600);
    CHECK(entries[0].mtimeNanoseconds == 7);
    CHECK(contents(*reader, entries[0]) == "data");
    CHECK(entries[1].path == "z");
    CHECK(entries[1].kind == EntryKind::HardLink);
    CHECK(entries[1].target == "a");
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("native hardlink chains canonicalize to the earliest path") {
    TempPath temp;
    auto writer = newWriter(temp.path());
    REQUIRE(writer.addHardLink("a", "b"));
    REQUIRE(writer.addHardLink("b", "c"));
    REQUIRE(writer.addBytes("c", bytesOf("chained")));
    REQUIRE(writer.finish());

    auto file = File::openRead(temp.path());
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    const auto& entries = reader->manifest().entries;
    REQUIRE(entries.size() == 3);
    CHECK(entries[0].path == "a");
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(contents(*reader, entries[0]) == "chained");
    CHECK(entries[1].kind == EntryKind::HardLink);
    CHECK(entries[1].target == "a");
    CHECK(entries[2].kind == EntryKind::HardLink);
    CHECK(entries[2].target == "a");
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("native self-links and cycles stay malformed at finish") {
    auto expectMalformed = [&](auto&& populate) {
        TempPath caseTemp;
        auto writer = newWriter(caseTemp.path(), fixedOptions());
        populate(writer);
        auto finished = writer.finish();
        REQUIRE_FALSE(finished);
        CHECK(finished.error().kind == ErrorKind::Malformed);
    };
    expectMalformed([](Writer& writer) {
        REQUIRE(writer.addHardLink("a", "a"));
    });
    expectMalformed([](Writer& writer) {
        REQUIRE(writer.addHardLink("a", "b"));
        REQUIRE(writer.addHardLink("b", "a"));
    });
    expectMalformed([](Writer& writer) {
        REQUIRE(writer.addHardLink("a", "b"));
        REQUIRE(writer.addHardLink("b", "missing"));
    });
    expectMalformed([](Writer& writer) {
        REQUIRE(writer.addDirectory("d"));
        REQUIRE(writer.addHardLink("a", "d"));
    });
}

TEST_CASE("native link-before-target archives extract in manifest order") {
    TempPath archiveTemp;
    TempPath workTemp;
    buildPair(archiveTemp.path(), true);

    auto file = File::openRead(archiveTemp.path());
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);

    std::filesystem::create_directories(workTemp.path() / "root");
    auto extractor = Extractor::open(workTemp.path() / "root");
    REQUIRE(extractor);
    for (const auto& entry : reader->manifest().entries) {
        if (entry.kind == EntryKind::Regular) {
            auto pending = extractor->beginFile(at(entry.path));
            REQUIRE(pending);
            auto streamed = reader->streamFile(entry, [&](std::span<const std::byte> chunk) {
                return pending->write(chunk);
            });
            REQUIRE(streamed);
            auto done = pending->commit();
            REQUIRE(done);
            CHECK(done->outcome == EntryOutcome::Extracted);
        } else {
            auto linked = extractor->createHardLink(at(entry.path), at(entry.target));
            REQUIRE(linked);
            CHECK(linked->outcome == EntryOutcome::Extracted);
        }
    }
    REQUIRE(extractor->finish());

    std::vector<std::byte> expected(bytesOf("data").begin(), bytesOf("data").end());
    CHECK(readAll(workTemp.path() / "root" / "a") == expected);
    CHECK(readAll(workTemp.path() / "root" / "z") == expected);
#ifndef _WIN32
    CHECK(std::filesystem::hard_link_count(workTemp.path() / "root" / "a") == 2);
#endif
}
