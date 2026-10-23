#include "cli/archive_commands.hpp"
#include "formats/sevenzip/reader.hpp"
#include "formats/sevenzip/sevenzip_fixture.hpp"
#include "formats/zip/reader.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <vector>

using namespace bale;
using bale::cli::ExitCode;

namespace {

void writeText(const std::filesystem::path& path, std::string_view data) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream stream(path, std::ios::binary);
    REQUIRE(stream);
    stream.write(data.data(), static_cast<std::streamsize>(data.size()));
}

std::map<std::string, std::string> readSevenZip(const std::filesystem::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = sevenzip::Reader::open(std::move(*file));
    REQUIRE(reader);
    std::map<std::string, std::string> out;
    std::vector<std::byte> scratch(8192);
    for (const auto& entry : reader->entries()) {
        if (entry.directory) {
            continue;
        }
        if (!entry.folder) {
            out[std::string(entry.name)] = "";
            continue;
        }
        std::string data;
        REQUIRE(reader->streamEntry(entry, scratch, [&data](std::span<const std::byte> chunk) {
            data.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        }));
        out[std::string(entry.name)] = data;
    }
    return out;
}

std::map<std::string, std::string> readZip(const std::filesystem::path& path) {
    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = zip::Reader::open(std::move(*file));
    REQUIRE(reader);
    std::map<std::string, std::string> out;
    std::vector<std::byte> scratch(8192);
    auto cursor = reader->entries();
    zip::Entry entry;
    std::string storage;
    while (true) {
        auto more = cursor.next(entry);
        REQUIRE(more);
        if (!*more) {
            return out;
        }
        auto name = zip::nameAsUtf8(entry, storage);
        REQUIRE(name);
        if (entry.unixMode && (*entry.unixMode & 0170000) == 0120000) {
            continue;
        }
        std::string data;
        REQUIRE(reader->streamEntry(entry, scratch, [&data](std::span<const std::byte> chunk) {
            data.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        }));
        out[std::string(*name)] = data;
    }
}

cli::CreateOptions sevenZipCreate(sevenzip::Codec codec, bool solid) {
    cli::CreateOptions options;
    options.format = cli::OutputFormat::SevenZip;
    options.sevenZipCodec = codec;
    options.sevenZipSolid = solid;
    return options;
}

}

TEST_CASE("sevenzip cli creates, lists and tests archives for every codec") {
    sevenzip::Codec codec = sevenzip::Codec::Lzma2;
    bool solid = true;
    SUBCASE("lzma2 solid") {
    }
    SUBCASE("lzma1 solid") {
        codec = sevenzip::Codec::Lzma1;
    }
    SUBCASE("deflate solid") {
        codec = sevenzip::Codec::Deflate;
    }
    SUBCASE("bzip2 solid") {
        codec = sevenzip::Codec::Bzip2;
    }
    SUBCASE("copy solid") {
        codec = sevenzip::Codec::Copy;
    }
    SUBCASE("lzma2 non-solid") {
        solid = false;
    }

    test::TempPath work;
    auto source = work.path() / "source";
    writeText(source / "hello.txt", "hello, 7z\n");
    writeText(source / "docs" / "notes.md", "# notes\n");
    writeText(source / "empty.txt", "");

    auto archive = work.path() / "out.7z";
    CHECK(
        cli::createArchive(archive.string(), source.string(), sevenZipCreate(codec, solid)) ==
        ExitCode::Ok
    );
    CHECK(cli::testArchive(archive.string()) == ExitCode::Ok);

    cli::ListOptions listOptions;
    CHECK(cli::listArchive(archive.string(), listOptions) == ExitCode::Ok);

    auto entries = readSevenZip(archive);
    REQUIRE(entries.size() == 3);
    CHECK(entries["hello.txt"] == "hello, 7z\n");
    CHECK(entries["docs/notes.md"] == "# notes\n");
    CHECK(entries["empty.txt"].empty());
}

TEST_CASE("sevenzip cli converts between zip and 7z without changing bytes") {
    test::TempPath work;
    auto source = work.path() / "source";
    writeText(source / "a.txt", "alpha\n");
    writeText(source / "b.bin", std::string(10'000, 'x'));
    writeText(source / "empty.txt", "");

    auto zipped = work.path() / "arch.zip";
    cli::CreateOptions zipOptions;
    zipOptions.format = cli::OutputFormat::Zip;
    REQUIRE(cli::createArchive(zipped.string(), source.string(), zipOptions) == ExitCode::Ok);

    auto converted = work.path() / "conv.7z";
    cli::ConvertOptions toSeven;
    toSeven.format = cli::OutputFormat::SevenZip;
    REQUIRE(cli::convertArchive(zipped.string(), converted.string(), toSeven) == ExitCode::Ok);
    CHECK(cli::testArchive(converted.string()) == ExitCode::Ok);
    auto fromZip = readSevenZip(converted);
    REQUIRE(fromZip.size() == 3);
    CHECK(fromZip["a.txt"] == "alpha\n");
    CHECK(fromZip["b.bin"] == std::string(10'000, 'x'));

    auto back = work.path() / "back.zip";
    cli::ConvertOptions toZip;
    toZip.format = cli::OutputFormat::Zip;
    REQUIRE(cli::convertArchive(converted.string(), back.string(), toZip) == ExitCode::Ok);
    auto fromSeven = readZip(back);
    CHECK(fromSeven == fromZip);
}

TEST_CASE("sevenzip cli update merges the directory over kept entries") {
    test::TempPath work;
    auto first = work.path() / "first";
    writeText(first / "a.txt", "version one\n");
    writeText(first / "b.txt", "kept\n");

    auto archive = work.path() / "up.7z";
    REQUIRE(
        cli::createArchive(
            archive.string(),
            first.string(),
            sevenZipCreate(sevenzip::Codec::Copy, true)
        ) == ExitCode::Ok
    );

    auto second = work.path() / "second";
    writeText(second / "a.txt", "version two\n");
    writeText(second / "c.txt", "added\n");

    cli::CreateOptions update;
    update.sevenZipCodec = sevenzip::Codec::Copy;
    REQUIRE(cli::updateArchive(archive.string(), second.string(), update) == ExitCode::Ok);
    CHECK(cli::testArchive(archive.string()) == ExitCode::Ok);

    auto entries = readSevenZip(archive);
    REQUIRE(entries.size() == 3);
    CHECK(entries["a.txt"] == "version two\n");
    CHECK(entries["b.txt"] == "kept\n");
    CHECK(entries["c.txt"] == "added\n");

    // NOTE: a second update with an empty directory keeps every entry.
    auto empty = work.path() / "empty";
    std::filesystem::create_directories(empty);
    REQUIRE(cli::updateArchive(archive.string(), empty.string(), update) == ExitCode::Ok);
    CHECK(readSevenZip(archive) == entries);
}

TEST_CASE("sevenzip cli update rewrites an archive written by real 7z") {
    std::string probeCommand = "7z i 2>&1";
    std::array<char, 128> chunk{};
    std::string banner;
    // NOLINTNEXTLINE(bugprone-command-processor)
    auto* pipe = ::popen(probeCommand.c_str(), "r");
    if (pipe == nullptr) {
        MESSAGE("7z is not installed; skipping foreign update");
        return;
    }
    while (std::fgets(chunk.data(), static_cast<int>(chunk.size()), pipe) != nullptr) {
        banner.append(chunk.data());
    }
    int probeStatus = ::pclose(pipe);
    if (probeStatus != 0 || banner.find("7-Zip") == std::string::npos) {
        MESSAGE("7z is not installed; skipping foreign update");
        return;
    }
    MESSAGE("foreign writer: " << banner.substr(0, banner.find('\n')));

    test::TempPath work;
    auto source = work.path() / "source";
    writeText(source / "r1.txt", "one\n");
    writeText(source / "r2.txt", "two\n");

    auto archive = work.path() / "foreign.7z";
    std::string add = std::string("7z a -t7z -mx=0 -y '") + archive.string() + "' '" +
        source.string() + "' > /dev/null 2>&1";
    // NOLINTNEXTLINE(bugprone-command-processor)
    REQUIRE(std::system(add.c_str()) == 0);

    auto overlay = work.path() / "overlay";
    writeText(overlay / "source" / "r2.txt", "TWO\n");
    writeText(overlay / "source" / "r3.txt", "three\n");

    cli::CreateOptions update;
    update.sevenZipCodec = sevenzip::Codec::Copy;
    REQUIRE(cli::updateArchive(archive.string(), overlay.string(), update) == ExitCode::Ok);
    CHECK(cli::testArchive(archive.string()) == ExitCode::Ok);

    auto entries = readSevenZip(archive);
    REQUIRE(entries.size() == 3);
    CHECK(entries["source/r1.txt"] == "one\n");
    CHECK(entries["source/r2.txt"] == "TWO\n");
    CHECK(entries["source/r3.txt"] == "three\n");

    std::string test = std::string("7z t '") + archive.string() + "' > /dev/null 2>&1";
    // NOLINTNEXTLINE(bugprone-command-processor)
    CHECK(std::system(test.c_str()) == 0);
}

TEST_CASE("sevenzip cli refuses what it cannot write") {
    CHECK_FALSE(cli::parseSevenZipCodec("ppmd"));
    CHECK_FALSE(cli::parseSevenZipCodec("aes"));
    CHECK(cli::parseSevenZipCodec("lzma2") == sevenzip::Codec::Lzma2);
    CHECK(cli::checkSevenZipLevel(sevenzip::Codec::Copy, 6));
    CHECK(cli::checkSevenZipLevel(sevenzip::Codec::Bzip2, 0));
    CHECK_FALSE(cli::checkSevenZipLevel(sevenzip::Codec::Bzip2, 9));
    CHECK_FALSE(cli::checkSevenZipLevel(sevenzip::Codec::Lzma2, 6));
    CHECK(cli::name(sevenzip::Codec::Deflate) == "deflate");

    test::TempPath work;
    writeText(work.path() / "plain.txt", "not an archive\n");

    cli::CreateOptions update;
    update.sevenZipCodec = sevenzip::Codec::Copy;
    CHECK(
        cli::updateArchive((work.path() / "plain.txt").string(), work.path().string(), update) ==
        ExitCode::Unsupported
    );

    sevenzip::test::SevenZipSpec spec;
    spec.codec = sevenzip::test::CodecKind::AesLzma2;
    spec.entries.push_back({.name = "secret.txt", .data = "classified"});
    auto built = sevenzip::test::buildSevenZip(spec);
    auto locked = work.path() / "locked.7z";
    {
        std::ofstream stream(locked, std::ios::binary);
        REQUIRE(stream);
        stream.write(
            reinterpret_cast<const char*>(built.bytes.data()),
            static_cast<std::streamsize>(built.bytes.size())
        );
    }
    auto overlay = work.path() / "overlay";
    writeText(overlay / "a.txt", "new\n");
    CHECK(
        cli::updateArchive(locked.string(), overlay.string(), update) == ExitCode::PasswordRequired
    );
}
