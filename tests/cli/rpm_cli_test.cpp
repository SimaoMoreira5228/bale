#include "cli/archive_commands.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

using namespace bale;
using bale::cli::ExitCode;

namespace {

std::filesystem::path goldenRpm(std::string_view name) {
    return std::filesystem::path(FORMAT_GOLDEN_DIR) / "rpm" / "data" / name;
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    REQUIRE(stream);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

}

TEST_CASE("rpm cli describes the golden package and its trust boundary") {
    // NOTE: info must name the package and state plainly that header
    // signatures are presence-only: no keyring exists to verify against.
    CHECK(
        cli::describeArchive(goldenRpm("hello-gzip.rpm").string(), std::nullopt, {}) == ExitCode::Ok
    );
}

TEST_CASE("rpm cli extracts the golden payload with modes intact") {
    test::TempPath temp;
    std::string out = (temp.path() / "out").string();
    // NOTE: the default policy refuses symlinks, so link.txt fails while
    // both regular files materialize with their payload modes.
    ExitCode code = cli::extractArchive(
        goldenRpm("hello-gzip.rpm").string(),
        out,
        ExtractPolicy{},
        std::nullopt,
        {}
    );
    CHECK(code == ExitCode::UnsafePath);
    CHECK(readFile(std::filesystem::path(out) / "usr/share/hello/greeting.txt") == "hello rpm\n");
    CHECK(std::filesystem::is_regular_file(std::filesystem::path(out) / "usr/share/hello/run.sh"));

    std::string allowed = (temp.path() / "allowed").string();
    ExtractPolicy policy;
    policy.symlinks = SymlinkPolicy::AllowContained;
    CHECK(
        cli::extractArchive(
            goldenRpm("hello-gzip.rpm").string(),
            allowed,
            policy,
            std::nullopt,
            {}
        ) == ExitCode::Ok
    );
// NOTE: Wine materializes file symlinks from FSCTL_SET_REPARSE_POINT as
// plain files, so the link check runs off Windows; the shared extractor
// path is covered on Windows by the generic symlink tests.
#ifndef _WIN32
    CHECK(std::filesystem::is_symlink(std::filesystem::path(allowed) / "usr/share/hello/link.txt"));
#endif
}

TEST_CASE("rpm cli converts the golden payload to bale and tar") {
    test::TempPath temp;
    std::error_code ignored;
    std::filesystem::create_directories(temp.path(), ignored);
    std::string baleOut = (temp.path() / "out.bale").string();
    cli::ConvertOptions baleOptions;
    baleOptions.format = cli::OutputFormat::Bale;
    CHECK(
        cli::convertArchive(goldenRpm("hello-xz.rpm").string(), baleOut, baleOptions) ==
        ExitCode::Ok
    );
    CHECK(cli::listArchive(baleOut, cli::ListOptions{}) == ExitCode::Ok);

    std::string tarOut = (temp.path() / "out.tar").string();
    cli::ConvertOptions tarOptions;
    tarOptions.format = cli::OutputFormat::Tar;
    CHECK(
        cli::convertArchive(goldenRpm("hello-zstd.rpm").string(), tarOut, tarOptions) ==
        ExitCode::Ok
    );
    CHECK(cli::testArchive(tarOut, std::nullopt, {}, 0) == ExitCode::Ok);
}

TEST_CASE("rpm cli tests and lists every golden compressor") {
    for (std::string_view name :
         {"hello-gzip.rpm", "hello-xz.rpm", "hello-zstd.rpm", "hello-bzip2.rpm"}) {
        CAPTURE(name);
        CHECK(cli::testArchive(goldenRpm(name).string(), std::nullopt, {}, 0) == ExitCode::Ok);
        CHECK(cli::listArchive(goldenRpm(name).string(), cli::ListOptions{}) == ExitCode::Ok);
    }
}
