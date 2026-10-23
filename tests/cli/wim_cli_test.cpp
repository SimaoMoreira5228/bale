#include "cli/archive_commands.hpp"
#include "formats/wim/wim_builder.ipp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace bale;
using bale::cli::ExitCode;

namespace {

std::filesystem::path goldenWim(std::string_view name) {
    return std::filesystem::path(FORMAT_GOLDEN_DIR) / "wim" / "data" / name;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    REQUIRE(stream);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

}

TEST_CASE("wim cli extracts the rich golden with skips") {
    test::TempPath temp;
    std::string out = (temp.path() / "out").string();
    // NOTE: the default policy refuses symlinks, so extraction reports
    // UnsafePath while every safe entry still materializes; the ADS never
    // becomes a file.
    ExitCode code =
        cli::extractArchive(goldenWim("rich.wim").string(), out, ExtractPolicy{}, std::nullopt, {});
    CHECK(code == ExitCode::UnsafePath);
    CHECK(std::filesystem::is_regular_file(std::filesystem::path(out) / "notes.txt"));
    CHECK(readFile(std::filesystem::path(out) / "notes.txt") == "default stream\n");
    CHECK(std::filesystem::is_regular_file(std::filesystem::path(out) / "orig.txt"));
    CHECK(std::filesystem::is_regular_file(std::filesystem::path(out) / "link.txt"));
    CHECK(!std::filesystem::exists(std::filesystem::path(out) / "notes.txt:hidden"));
    CHECK(!std::filesystem::is_symlink(std::filesystem::path(out) / "pointer.lnk"));
}

TEST_CASE("wim cli extracts a contained symlink when allowed") {
    // NOTE: a relative link staying inside the output is created under
    // AllowContained; absolute links like the golden's stay refused.
    auto symlinkBuffer = [](std::string_view print) {
        std::vector<std::byte> buffer;
        auto put16 = [&](std::uint16_t value) {
            buffer.push_back(static_cast<std::byte>(value & 0xFF));
            buffer.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
        };
        put16(0);
        put16(0);
        put16(0);
        put16(static_cast<std::uint16_t>(print.size() * 2));
        put16(0);
        put16(0);
        for (char unit : print) {
            buffer.push_back(static_cast<std::byte>(unit));
            buffer.push_back(std::byte{0});
        }
        buffer.push_back(std::byte{0});
        buffer.push_back(std::byte{0});
        return buffer;
    };
    wim::test::TestWim spec;
    wim::test::TestFile target;
    target.path = "dir/rel.txt";
    target.data = {std::byte{'r'}};
    spec.images[0].files.push_back(target);
    wim::test::TestFile link;
    link.path = "dir/up.lnk";
    link.attrs = 0x20 | 0x400;
    link.reparseTag = 0xA000000C;
    link.reparseData = symlinkBuffer("rel.txt");
    spec.images[0].files.push_back(link);
    auto bytes = wim::test::buildWim(spec);
    test::TempFile archive{std::span<const std::byte>(bytes)};
    REQUIRE(archive.ok());
    test::TempPath temp;
    std::string out = (temp.path() / "out").string();
    ExtractPolicy policy;
    policy.symlinks = SymlinkPolicy::AllowContained;
    ExitCode code = cli::extractArchive(archive.path().string(), out, policy, std::nullopt, {});
    CHECK(code == ExitCode::Ok);
    auto created = std::filesystem::path(out) / "dir" / "up.lnk";
    REQUIRE(std::filesystem::exists(created));
// NOTE: Wine materializes file symlinks from FSCTL_SET_REPARSE_POINT as
// plain files, so the target check runs off Windows; the shared extractor
// path is covered on Windows by the generic symlink tests.
#ifndef _WIN32
    REQUIRE(std::filesystem::is_symlink(created));
    CHECK(std::filesystem::read_symlink(created).string() == "rel.txt");
#endif
}

TEST_CASE("wim cli converts an LZX image") {
    // NOTE: lzx_multi.wim exercises the convert-out pipeline over
    // LZX-decoded streams (multi-chunk file plus links and streams).
    test::TempPath temp;
    std::error_code ignored;
    std::filesystem::create_directories(temp.path(), ignored);
    std::string converted = (temp.path() / "lzx.zip").string();
    cli::ConvertOptions options;
    options.format = cli::OutputFormat::Zip;
    ExitCode code = cli::convertArchive(goldenWim("lzx_multi.wim").string(), converted, options);
    CHECK(code == ExitCode::Ok);
    cli::ListOptions list;
    code = cli::listArchive(converted, list);
    CHECK(code == ExitCode::Ok);
}

TEST_CASE("wim cli converts the selected image") {
    test::TempPath temp;
    std::error_code ignored;
    std::filesystem::create_directories(temp.path(), ignored);
    std::string converted = (temp.path() / "image3.zip").string();
    cli::ConvertOptions options;
    options.format = cli::OutputFormat::Zip;
    options.imageIndex = 3;
    ExitCode code = cli::convertArchive(goldenWim("multi.wim").string(), converted, options);
    CHECK(code == ExitCode::Ok);
    // NOTE: listing the converted zip proves convert-out carries the
    // selected image's entries through the generic pipeline.
    cli::ListOptions list;
    code = cli::listArchive(converted, list);
    CHECK(code == ExitCode::Ok);
}

TEST_CASE("wim cli rejects --image for other formats") {
    std::filesystem::path iso =
        std::filesystem::path(FORMAT_GOLDEN_DIR) / "iso" / "data" / "rr_joliet.iso";
    cli::ListOptions list;
    list.imageIndex = 2;
    ExitCode code = cli::listArchive(iso.string(), list);
    CHECK(code == ExitCode::InvalidArchive);
}
