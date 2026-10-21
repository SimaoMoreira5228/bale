#include "formats/tar/writer.hpp"

#include "formats/compressed/output.hpp"
#include "formats/tar/reader.hpp"
#include "formats/tar/source.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <span>
#include <string>
#include <utility>
#include <vector>

using namespace bale;
using namespace bale::tar;

namespace {

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

Writer createWriter(const std::filesystem::path& path) {
    auto file = File::createNew(path);
    REQUIRE(file);
    auto output = CompressedOutput::create(std::move(*file), Compression::None);
    REQUIRE(output);
    return Writer(std::move(*output));
}

struct Listed {
    std::string path;
    EntryKind kind = EntryKind::Regular;
    std::string target;
    std::string data;
};

std::vector<Listed> readAll(const std::filesystem::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto source = Source::open(std::move(*file));
    REQUIRE(source);
    Reader reader(std::move(*source));
    std::vector<Listed> entries;
    std::vector<std::byte> scratch(4096);
    while (true) {
        auto next = reader.next();
        REQUIRE(next);
        if (*next == nullptr) {
            return entries;
        }
        Listed listed{
            .path = std::string((*next)->path),
            .kind = (*next)->kind,
            .target = std::string((*next)->linkTarget),
            .data = {},
        };
        auto streamed = reader.streamData(scratch, [&](std::span<const std::byte> chunk) {
            listed.data.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        REQUIRE(streamed);
        entries.push_back(std::move(listed));
    }
}

WriteEntry regular(std::string_view path, std::uint64_t size) {
    return WriteEntry{.path = path, .size = size, .mode = 0644};
}

WriteEntry hardLink(std::string_view path, std::string_view target) {
    return WriteEntry{
        .path = path,
        .linkTarget = target,
        .mode = 0644,
        .kind = EntryKind::HardLink
    };
}

std::vector<std::byte> readBytes(const std::filesystem::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto size = file->size();
    REQUIRE(size);
    std::vector<std::byte> data(static_cast<std::size_t>(*size));
    REQUIRE(file->readExactAt(0, data));
    return data;
}

} // namespace

TEST_CASE("tar defers link-before-target until its target is written") {
    bale::test::TempPath deferredTemp;
    bale::test::TempPath orderedTemp;
    {
        auto writer = createWriter(deferredTemp.path());
        REQUIRE(writer.add(hardLink("a", "z")));
        REQUIRE(writer.add(regular("z", 4)));
        REQUIRE(writer.write(bytesOf("data")));
        REQUIRE(writer.finish());
    }
    {
        auto writer = createWriter(orderedTemp.path());
        REQUIRE(writer.add(regular("z", 4)));
        REQUIRE(writer.write(bytesOf("data")));
        REQUIRE(writer.add(hardLink("a", "z")));
        REQUIRE(writer.finish());
    }
    CHECK(readBytes(deferredTemp.path()) == readBytes(orderedTemp.path()));

    auto entries = readAll(deferredTemp.path());
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].path == "z");
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(entries[0].data == "data");
    CHECK(entries[1].path == "a");
    CHECK(entries[1].kind == EntryKind::HardLink);
    CHECK(entries[1].target == "z");
}

TEST_CASE("tar already-ordered links keep their exact positions") {
    bale::test::TempPath temp;
    auto writer = createWriter(temp.path());
    REQUIRE(writer.add(regular("z", 4)));
    REQUIRE(writer.write(bytesOf("data")));
    REQUIRE(writer.add(hardLink("a", "z")));
    REQUIRE(writer.add(hardLink("m", "z")));
    REQUIRE(writer.finish());

    auto entries = readAll(temp.path());
    REQUIRE(entries.size() == 3);
    CHECK(entries[0].path == "z");
    CHECK(entries[1].path == "a");
    CHECK(entries[1].target == "z");
    CHECK(entries[2].path == "m");
    CHECK(entries[2].target == "z");
}

TEST_CASE("tar deep chains flush in dependency order") {
    bale::test::TempPath temp;
    auto writer = createWriter(temp.path());
    REQUIRE(writer.add(hardLink("a", "b")));
    REQUIRE(writer.add(hardLink("b", "c")));
    REQUIRE(writer.add(regular("c", 4)));
    REQUIRE(writer.write(bytesOf("data")));
    REQUIRE(writer.finish());

    auto entries = readAll(temp.path());
    REQUIRE(entries.size() == 3);
    CHECK(entries[0].path == "c");
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(entries[0].data == "data");
    CHECK(entries[1].path == "b");
    CHECK(entries[1].kind == EntryKind::HardLink);
    CHECK(entries[1].target == "c");
    CHECK(entries[2].path == "a");
    CHECK(entries[2].kind == EntryKind::HardLink);
    CHECK(entries[2].target == "b");
}

TEST_CASE("tar dangling and cyclic links fail at finish") {
    auto expectMalformed = [](auto&& populate) {
        bale::test::TempPath caseTemp;
        auto writer = createWriter(caseTemp.path());
        populate(writer);
        auto finished = writer.finish();
        REQUIRE_FALSE(finished);
        CHECK(finished.error().kind == ErrorKind::Malformed);
    };
    expectMalformed([](Writer& writer) {
        REQUIRE(writer.add(hardLink("b", "missing")));
    });
    expectMalformed([](Writer& writer) {
        REQUIRE(writer.add(hardLink("a", "a")));
    });
    expectMalformed([](Writer& writer) {
        REQUIRE(writer.add(hardLink("a", "b")));
        REQUIRE(writer.add(hardLink("b", "a")));
    });
    expectMalformed([](Writer& writer) {
        REQUIRE(writer.add(hardLink("a", "b")));
        REQUIRE(writer.add(hardLink("b", "missing")));
    });
}
