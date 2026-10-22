#include "formats/sevenzip/writer.hpp"

#include "checksum/crc.hpp"
#include "formats/sevenzip/header.hpp"
#include "formats/sevenzip/reader.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdio>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

using namespace bale;
using namespace bale::sevenzip;

namespace {

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

struct Written {
    test::TempPath temp;
    std::uint64_t size = 0;
};

Writer openWriter(const std::filesystem::path& path, const WriterOptions& options = {}) {
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = Writer::create(std::move(*file), options);
    REQUIRE(writer);
    return std::move(*writer);
}

std::vector<std::byte> readAll(const std::filesystem::path& path, std::uint64_t size) {
    auto file = File::openRead(path);
    REQUIRE(file);
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    REQUIRE(file->readExactAt(0, bytes));
    return bytes;
}

Reader openReader(const std::filesystem::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    return std::move(*reader);
}

std::string contentsOf(Reader& reader, const Entry& entry) {
    std::string out;
    std::vector<std::byte> scratch(8192);
    REQUIRE(reader.streamEntry(entry, scratch, [&out](std::span<const std::byte> chunk) {
        out.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    }));
    return out;
}

std::string largeText() {
    std::string large(100'000, '-');
    for (std::size_t index = 0; index < large.size(); index += 41) {
        large[index] = static_cast<char>('A' + index % 23);
    }
    return large;
}

void addMixed(Writer& writer, bool chunked = false) {
    constexpr std::int64_t mtime = 1'700'000'000'000'000'000LL;
    REQUIRE(writer.add(
        {.path = "docs", .mtimeNanoseconds = mtime, .mode = 040755, .kind = WriteKind::Directory}
    ));
    REQUIRE(writer.add({
        .path = "docs/readme.txt",
        .size = 20,
        .mtimeNanoseconds = mtime,
        .mode = 0100644,
    }));
    if (chunked) {
        REQUIRE(writer.write(bytesOf("hello, ")));
        REQUIRE(writer.write(bytesOf("stored world\n")));
    } else {
        REQUIRE(writer.write(bytesOf("hello, stored world\n")));
    }
    REQUIRE(writer.add({.path = "docs/empty.txt", .mtimeNanoseconds = mtime}));
    REQUIRE(writer.add({.path = "docs/café.txt", .size = 11, .mtimeNanoseconds = mtime}));
    REQUIRE(writer.write(bytesOf("utf-8 name\n")));
    REQUIRE(writer.add({
        .path = "docs/link",
        .linkTarget = "readme.txt",
        .mtimeNanoseconds = mtime,
        .kind = WriteKind::Symlink,
    }));
}

void checkMixed(Reader& reader) {
    REQUIRE(reader.entryCount() == 5);
    auto entries = std::vector<Entry>(reader.entries().begin(), reader.entries().end());
    REQUIRE(entries.size() == 5);
    CHECK(entries[0].name == "docs");
    CHECK(entries[0].directory);
    CHECK(entries[0].mode == 040755);
    CHECK(entries[0].mtimeNanoseconds == 1'700'000'000'000'000'000LL);
    CHECK(entries[1].name == "docs/readme.txt");
    CHECK(entries[1].size == 20);
    CHECK_FALSE(entries[1].directory);
    CHECK(contentsOf(reader, entries[1]) == "hello, stored world\n");
    CHECK(entries[2].name == "docs/empty.txt");
    CHECK(entries[2].size == 0);
    CHECK_FALSE(entries[2].folder);
    CHECK(entries[3].name == "docs/café.txt");
    CHECK(contentsOf(reader, entries[3]) == "utf-8 name\n");
    CHECK(entries[4].name == "docs/link");
    CHECK(contentsOf(reader, entries[4]) == "readme.txt");
    CHECK(entries[4].mode == 0120777);
}

}

TEST_CASE("7z writer round-trips every supported codec through the reader") {
    Codec codec = Codec::Lzma2;
    SUBCASE("Copy") {
        codec = Codec::Copy;
    }
    SUBCASE("LZMA1") {
        codec = Codec::Lzma1;
    }
    SUBCASE("LZMA2") {
        codec = Codec::Lzma2;
    }
    SUBCASE("Deflate") {
        codec = Codec::Deflate;
    }
    SUBCASE("BZip2") {
        codec = Codec::Bzip2;
    }

    test::TempPath temp;
    auto writer = openWriter(temp.path(), {.codec = codec});
    std::string large = largeText();
    REQUIRE(writer.add({.path = "large.txt", .size = large.size()}));
    REQUIRE(writer.write(bytesOf(large)));
    REQUIRE(writer.add({.path = "small.txt", .size = 7}));
    REQUIRE(writer.write(bytesOf("payload")));
    auto size = writer.finish();
    REQUIRE(size);
    CHECK(*size > 32);

    auto reader = openReader(temp.path());
    REQUIRE(reader.entryCount() == 2);
    REQUIRE(reader.folderCount() == 1);
    auto entries = std::vector<Entry>(reader.entries().begin(), reader.entries().end());
    CHECK(entries[0].size == large.size());
    CHECK(entries[0].offset == 0);
    CHECK(entries[1].offset == large.size());
    CHECK(contentsOf(reader, entries[0]) == large);
    CHECK(contentsOf(reader, entries[1]) == "payload");

    std::uint64_t covered = 0;
    for (const auto& entry : entries) {
        covered += entry.size;
    }
    CHECK(covered == large.size() + 7);
}

TEST_CASE("7z writer round-trips mixed entries with metadata in one solid block") {
    for (bool chunked : {false, true}) {
        test::TempPath temp;
        auto writer = openWriter(temp.path(), {.codec = Codec::Lzma2});
        addMixed(writer, chunked);
        auto size = writer.finish();
        REQUIRE(size);

        auto reader = openReader(temp.path());
        CHECK(reader.folderCount() == 1);
        checkMixed(reader);
    }
}

TEST_CASE("7z writer lays out one folder per file when solid is off") {
    test::TempPath temp;
    auto writer = openWriter(temp.path(), {.codec = Codec::Deflate, .solid = false});
    addMixed(writer);
    auto size = writer.finish();
    REQUIRE(size);

    auto reader = openReader(temp.path());
    CHECK(reader.folderCount() == 3);
    checkMixed(reader);
}

TEST_CASE("7z writer round-trips empty archives and directories alone") {
    test::TempPath empty;
    auto nothing = openWriter(empty.path());
    auto emptySize = nothing.finish();
    REQUIRE(emptySize);
    auto emptyReader = openReader(empty.path());
    CHECK(emptyReader.entryCount() == 0);

    test::TempPath dirs;
    auto dirWriter = openWriter(dirs.path());
    REQUIRE(dirWriter.add({.path = "a", .kind = WriteKind::Directory}));
    REQUIRE(dirWriter.add({.path = "a/b/", .kind = WriteKind::Directory}));
    auto dirSize = dirWriter.finish();
    REQUIRE(dirSize);
    auto dirReader = openReader(dirs.path());
    REQUIRE(dirReader.entryCount() == 2);
    auto entries = std::vector<Entry>(dirReader.entries().begin(), dirReader.entries().end());
    CHECK(entries[0].name == "a");
    CHECK(entries[0].directory);
    CHECK(entries[1].name == "a/b");
    CHECK(entries[1].directory);
}

TEST_CASE("7z writer output is byte-deterministic for identical inputs") {
    auto build = [](bool chunked, std::optional<std::int64_t> mtime) {
        test::TempPath temp;
        auto writer = openWriter(temp.path(), {.codec = Codec::Lzma2});
        constexpr std::string_view first = "first file contents";
        constexpr std::string_view second = "second file contents, a bit longer";
        REQUIRE(writer.add({.path = "a.txt", .size = first.size(), .mtimeNanoseconds = mtime}));
        if (chunked) {
            REQUIRE(writer.write(bytesOf(first.substr(0, 5))));
            REQUIRE(writer.write(bytesOf(first.substr(5))));
        } else {
            REQUIRE(writer.write(bytesOf(first)));
        }
        REQUIRE(writer.add({.path = "b.txt", .size = second.size(), .mtimeNanoseconds = mtime}));
        REQUIRE(writer.write(bytesOf(second)));
        auto size = writer.finish();
        REQUIRE(size);
        return readAll(temp.path(), *size);
    };

    auto whole = build(false, 1'700'000'000'000'000'000LL);
    auto split = build(true, 1'700'000'000'000'000'000LL);
    CHECK(whole == split);
    auto timeless = build(false, std::nullopt);
    CHECK(timeless != whole);
    auto retimed = build(false, 1'700'000'001'000'000'000LL);
    CHECK(retimed != whole);
}

TEST_CASE("7z writer emits only single-coder folders the reader supports") {
    for (Codec codec : {Codec::Copy, Codec::Lzma1, Codec::Lzma2, Codec::Deflate, Codec::Bzip2}) {
        test::TempPath temp;
        auto writer = openWriter(temp.path(), {.codec = codec});
        REQUIRE(writer.add({.path = "a.txt", .size = 4}));
        REQUIRE(writer.write(bytesOf("data")));
        auto size = writer.finish();
        REQUIRE(size);
        auto bytes = readAll(temp.path(), *size);

        auto signature = readSignature(*File::openRead(temp.path()), {});
        REQUIRE(signature);
        auto model = parseHeader(signature->bytes, signature->headerOffset, {});
        REQUIRE(model);
        REQUIRE_FALSE(model->folders.empty());
        for (const auto& folder : model->folders) {
            CHECK(folder.coders.size() == 1);
            auto info = resolveCodec(folder);
            CHECK(info.supported);
            CHECK_FALSE(info.encrypted);
            CHECK(folder.numPackedStreams == 1);
        }
    }
}

TEST_CASE("7z writer enforces budgets and entry rules") {
    SUBCASE("entry count") {
        test::TempPath temp;
        auto writer = openWriter(temp.path(), {.limits = {.maxEntries = 1}});
        REQUIRE(writer.add({.path = "a.txt", .size = 1}));
        REQUIRE(writer.write(bytesOf("x")));
        CHECK_FALSE(writer.add({.path = "b.txt", .size = 1}));
    }
    SUBCASE("header bytes") {
        test::TempPath temp;
        auto writer = openWriter(temp.path(), {.limits = {.maxHeaderBytes = 32}});
        REQUIRE(writer.add({.path = "a.txt", .size = 1}));
        REQUIRE(writer.write(bytesOf("x")));
        auto size = writer.finish();
        REQUIRE_FALSE(size);
        CHECK(size.error().kind == ErrorKind::LimitExceeded);
    }
    SUBCASE("entry bytes") {
        test::TempPath temp;
        auto writer = openWriter(temp.path(), {.limits = {.maxEntryBytes = 2}});
        CHECK_FALSE(writer.add({.path = "a.txt", .size = 3}));
    }
    SUBCASE("duplicate names") {
        test::TempPath temp;
        auto writer = openWriter(temp.path());
        REQUIRE(writer.add({.path = "a.txt", .size = 1}));
        REQUIRE(writer.write(bytesOf("x")));
        auto again = writer.add({.path = "a.txt", .size = 1});
        REQUIRE_FALSE(again);
        CHECK(again.error().kind == ErrorKind::AlreadyExists);
    }
    SUBCASE("short and long writes") {
        test::TempPath temp;
        auto writer = openWriter(temp.path());
        REQUIRE(writer.add({.path = "a.txt", .size = 4}));
        REQUIRE(writer.write(bytesOf("da")));
        CHECK_FALSE(writer.add({.path = "b.txt", .size = 1}));

        test::TempPath over;
        auto overWriter = openWriter(over.path());
        REQUIRE(overWriter.add({.path = "a.txt", .size = 2}));
        CHECK_FALSE(overWriter.write(bytesOf("too long")));
    }
    SUBCASE("levels") {
        for (Codec codec : {Codec::Lzma1, Codec::Lzma2, Codec::Deflate}) {
            test::TempPath temp;
            auto file = File::createNew(temp.path());
            REQUIRE(file);
            CHECK_FALSE(Writer::create(std::move(*file), {.codec = codec, .level = 99}));
        }
        test::TempPath temp;
        auto file = File::createNew(temp.path());
        REQUIRE(file);
        CHECK_FALSE(Writer::create(std::move(*file), {.codec = Codec::Bzip2, .level = 0}));
    }
    SUBCASE("names") {
        test::TempPath temp;
        auto writer = openWriter(temp.path());
        CHECK_FALSE(writer.add({.path = "", .size = 1}));
        std::string embeddedNul("bad\0name", 8);
        CHECK_FALSE(writer.add({.path = embeddedNul, .size = 1}));
        CHECK_FALSE(writer.add({.path = std::string("\xff\xfe"), .size = 1}));
    }
}

TEST_CASE("7z writer archives fail loudly on read-back corruption") {
    test::TempPath temp;
    auto writer = openWriter(temp.path(), {.codec = Codec::Lzma2});
    addMixed(writer);
    auto size = writer.finish();
    REQUIRE(size);
    auto bytes = readAll(temp.path(), *size);

    SUBCASE("pack corruption") {
        auto broken = bytes;
        broken[32] ^= std::byte{0xFF};
        test::TempFile tempFile(broken);
        REQUIRE(tempFile.ok());
        auto reader = Reader::open(*tempFile.open());
        REQUIRE(reader);
        std::vector<std::byte> scratch(256);
        auto entries = std::vector<Entry>(reader->entries().begin(), reader->entries().end());
        auto streamed = reader->streamEntry(entries[1], scratch, [](std::span<const std::byte>) {
            return Result<void>{};
        });
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::Integrity);
    }
    SUBCASE("header corruption") {
        auto broken = bytes;
        broken.back() ^= std::byte{0xFF};
        test::TempFile tempFile(broken);
        REQUIRE(tempFile.ok());
        auto reader = Reader::open(*tempFile.open());
        if (reader) {
            std::vector<std::byte> scratch(256);
            bool failed = false;
            for (const auto& entry : reader->entries()) {
                auto streamed = reader->streamEntry(entry, scratch, [](std::span<const std::byte>) {
                    return Result<void>{};
                });
                failed = failed || !streamed;
            }
            CHECK(failed);
        }
    }
}

namespace {

bool haveSevenZip(std::string* banner = nullptr) {
    std::string command = "7z 2>&1";
    std::array<char, 256> chunk{};
    std::string output;
    // NOLINTNEXTLINE(bugprone-command-processor)
    auto* pipe = ::popen(command.c_str(), "r");
    if (pipe == nullptr) {
        return false;
    }
    while (std::fgets(chunk.data(), static_cast<int>(chunk.size()), pipe) != nullptr) {
        output.append(chunk.data());
    }
    int status = ::pclose(pipe);
    if (banner != nullptr) {
        *banner = output.substr(0, output.find('\n'));
    }
    return status == 0 && output.find("7-Zip") != std::string::npos;
}

int runSevenZip(std::string_view args, std::string* output = nullptr) {
    std::string command("7z ");
    command.append(args);
    command += " 2>&1";
    std::array<char, 256> chunk{};
    std::string text;
    // NOLINTNEXTLINE(bugprone-command-processor)
    auto* pipe = ::popen(command.c_str(), "r");
    if (pipe == nullptr) {
        return -1;
    }
    while (std::fgets(chunk.data(), static_cast<int>(chunk.size()), pipe) != nullptr) {
        text.append(chunk.data());
    }
    if (output != nullptr) {
        *output = text;
    }
    return ::pclose(pipe);
}

}

TEST_CASE("7z writer output passes the real 7-Zip extractor") {
    std::string banner;
    if (!haveSevenZip(&banner)) {
        MESSAGE("7z is not installed; skipping differential extraction");
        return;
    }
    MESSAGE("differential extractor: " << banner);

    Codec codec = Codec::Lzma2;
    bool solid = true;
    SUBCASE("lzma2 solid") {
        codec = Codec::Lzma2;
    }
    SUBCASE("lzma1 solid") {
        codec = Codec::Lzma1;
    }
    SUBCASE("deflate solid") {
        codec = Codec::Deflate;
    }
    SUBCASE("bzip2 solid") {
        codec = Codec::Bzip2;
    }
    SUBCASE("copy solid") {
        codec = Codec::Copy;
    }
    SUBCASE("lzma2 non-solid") {
        solid = false;
    }

    test::TempPath archive;
    {
        auto writer = openWriter(archive.path(), {.codec = codec, .solid = solid});
        addMixed(writer);
        std::string large = largeText();
        REQUIRE(writer.add({.path = "large.bin", .size = large.size()}));
        REQUIRE(writer.write(bytesOf(large)));
        REQUIRE(writer.finish());
    }

    std::string listed;
    int listStatus = runSevenZip(std::string("l '") + archive.path().string() + "'", &listed);
    MESSAGE("7z l output: " << listed);
    CHECK(listStatus == 0);

    test::TempPath outDir;
    std::filesystem::create_directories(outDir.path());
    int extractStatus = runSevenZip(
        std::string("x -y -o'") + (outDir.path() / "root").string() + "' '" +
        archive.path().string() + "'"
    );
    CHECK(extractStatus == 0);

    auto root = outDir.path() / "root";
    auto readText = [](const std::filesystem::path& path) {
        std::ifstream stream(path, std::ios::binary);
        REQUIRE(stream);
        return std::string(
            std::istreambuf_iterator<char>(stream),
            std::istreambuf_iterator<char>()
        );
    };
    CHECK(readText(root / "docs" / "readme.txt") == "hello, stored world\n");
    CHECK(readText(root / "large.bin") == largeText());
}

TEST_CASE("7z writer single-stream folders with empty entries pass the real 7-Zip") {
    // NOTE: real 7-Zip rejects folder CRCs in single-substream folders
    // alongside empty entries, so the writer omits them everywhere; this
    // locks that layout against every codec, solid and non-solid.
    std::string banner;
    if (!haveSevenZip(&banner)) {
        MESSAGE("7z is not installed; skipping differential extraction");
        return;
    }
    MESSAGE("differential extractor: " << banner);

    Codec codec = Codec::Lzma2;
    bool solid = true;
    SUBCASE("lzma2 solid") {
    }
    SUBCASE("copy solid") {
        codec = Codec::Copy;
    }
    SUBCASE("deflate non-solid") {
        codec = Codec::Deflate;
        solid = false;
    }

    test::TempPath archive;
    {
        auto writer = openWriter(archive.path(), {.codec = codec, .solid = solid});
        REQUIRE(writer.add({.path = "empty.txt"}));
        REQUIRE(writer.add({.path = "one.txt", .size = 4}));
        REQUIRE(writer.write(bytesOf("one\n")));
        REQUIRE(writer.finish());
    }

    std::string tested;
    CHECK(runSevenZip(std::string("t '") + archive.path().string() + "'", &tested) == 0);
    if (tested.find("Everything is Ok") == std::string::npos) {
        MESSAGE("7z test output: " << tested);
    }
    CHECK(tested.find("Everything is Ok") != std::string::npos);
}
