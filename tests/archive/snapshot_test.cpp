#include "archive/reader.hpp"
#include "archive/writer.hpp"

#include "archive/archive_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::contents;
using bale::test::newWriter;
using bale::test::TempPath;

TEST_CASE("append writes a linked snapshot and reuses indexed chunks") {
    TempPath temp;
    {
        auto writer = newWriter(temp.path());
        REQUIRE(writer.addBytes("old", bytesOf("shared")));
        REQUIRE(writer.finish());
    }
    {
        auto tail = File::openAppend(temp.path());
        REQUIRE(tail);
        std::vector<std::byte> interrupted(127, std::byte{0xA5});
        REQUIRE(tail->append(interrupted));
    }

    auto file = File::openAppend(temp.path());
    REQUIRE(file);
    auto writer = Writer::append(std::move(*file));
    REQUIRE(writer);
    REQUIRE(writer->addBytes("new", bytesOf("shared")));
    auto summary = writer->finish();
    REQUIRE(summary);
    CHECK(summary->dataRecords == 1);
    CHECK(summary->chunkReferences == 1);

    auto input = File::openRead(temp.path());
    REQUIRE(input);
    auto reader = Reader::open(std::move(*input));
    REQUIRE(reader);
    CHECK(reader->commit().generation == 2);
    CHECK(reader->ignoredTrailingBytes() == 0);
    CHECK(reader->commit().previous != Blake3Digest{});
    REQUIRE(reader->manifest().entries.size() == 1);
    CHECK(reader->manifest().entries.front().path == "new");
    CHECK(contents(*reader, reader->manifest().entries.front()) == "shared");

    auto verified = reader->verify(VerifyMode::Content);
    REQUIRE(verified);
    CHECK(verified->chunksVerified == 1);
}

TEST_CASE("compaction keeps the current snapshot and drops obsolete chunks") {
    TempPath sourceTemp;
    TempPath compactedTemp;
    const auto& sourcePath = sourceTemp.path();
    const auto& compactedPath = compactedTemp.path();
    {
        auto writer = newWriter(sourcePath);
        REQUIRE(writer.addBytes("old", bytesOf("obsolete")));
        REQUIRE(writer.finish());
    }
    {
        auto file = File::openAppend(sourcePath);
        REQUIRE(file);
        WriterOptions options;
        options.comment = "snapshot comment";
        auto writer = Writer::append(std::move(*file), options);
        REQUIRE(writer);
        REQUIRE(writer->addDirectory("dir", {.mtimeNanoseconds = 0, .mode = 0755}));
        REQUIRE(writer->addBytes("dir/kept", bytesOf("shared"), {.mode = 0640}));
        REQUIRE(writer->addBytes("copy", bytesOf("shared")));
        REQUIRE(writer->addHardLink("hard", "dir/kept"));
        REQUIRE(writer->addSymlink("link", "dir/kept"));
        REQUIRE(writer->finish());
    }

    auto sourceFile = File::openRead(sourcePath);
    REQUIRE(sourceFile);
    auto source = Reader::open(std::move(*sourceFile));
    REQUIRE(source);
    REQUIRE(source->commit().generation == 2);
    REQUIRE(source->index().size() == 2);

    auto output = File::createNew(compactedPath);
    REQUIRE(output);
    auto summary = Writer::compact(std::move(*output), *source);
    REQUIRE(summary);
    CHECK(summary->entries == 5);
    CHECK(summary->dataRecords == 1);
    CHECK(summary->chunkReferences == 2);

    auto compactedFile = File::openRead(compactedPath);
    REQUIRE(compactedFile);
    auto compacted = Reader::open(std::move(*compactedFile));
    REQUIRE(compacted);
    CHECK(compacted->commit().generation == 1);
    CHECK(compacted->superblock().archiveId == source->superblock().archiveId);
    CHECK(compacted->superblock().creationTimeNs == source->superblock().creationTimeNs);
    CHECK(compacted->manifest().comment == "snapshot comment");
    CHECK(compacted->manifest().entries.size() == 5);
    CHECK(compacted->index().size() == 1);
    CHECK(compacted->manifest().entries[0].path == "copy");
    CHECK(compacted->manifest().entries[1].kind == EntryKind::Directory);
    CHECK(compacted->manifest().entries[1].mtimeNanoseconds == 0);
    CHECK(compacted->manifest().entries[2].path == "dir/kept");
    CHECK(compacted->manifest().entries[2].mode == 0640);
    CHECK(compacted->manifest().entries[3].kind == EntryKind::HardLink);
    CHECK(compacted->manifest().entries[3].target == "dir/kept");
    CHECK(compacted->manifest().entries[4].kind == EntryKind::Symlink);
    CHECK(compacted->manifest().entries[4].target == "dir/kept");
    CHECK(contents(*compacted, compacted->manifest().entries[0]) == "shared");
    CHECK(contents(*compacted, compacted->manifest().entries[2]) == "shared");
    CHECK(compacted->verify(VerifyMode::Content));

    CHECK(source->commit().generation == 2);
    CHECK(source->index().size() == 2);
}
