#include "cli/archive_commands.hpp"

#include "codecs/codec_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <string>
#include <string_view>
#include <vector>

using namespace bale;

namespace {

std::string
nameFor(std::string_view archive, const std::vector<std::byte>& bytes, Compression compression) {
    test::TempFile temp(bytes);
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    auto stream = CompressedStream::open(std::move(*file), compression);
    REQUIRE(stream);

    std::string out;
    auto path = cli::singleFileName(archive, *stream, out);
    REQUIRE(path);
    CHECK(path->depth == 1);
    return std::string(path->path);
}

std::string gzipNamed(std::string_view archive, std::string_view storedName) {
    std::vector<std::byte> data(10, std::byte{'d'});
    return nameFor(archive, test::gzipMember(data, storedName), Compression::Gzip);
}

}

TEST_CASE("singleFileName trusts a gzip FNAME only when it is one safe component") {
    CHECK(gzipNamed("downloads/archive.gz", "report.txt") == "report.txt");
    CHECK(gzipNamed("downloads/archive.gz", "") == "archive");
    CHECK(gzipNamed("downloads/archive.gz", "../../etc/passwd") == "archive");
    CHECK(gzipNamed("downloads/archive.gz", "/etc/passwd") == "archive");
    CHECK(gzipNamed("downloads/archive.gz", "sub/file.txt") == "archive");
    CHECK(gzipNamed("downloads/archive.gz", "..") == "archive");
    CHECK(gzipNamed("downloads/archive.gz", "caf\xE9.txt") == "archive");
    CHECK(gzipNamed("downloads/archive.gz", "con") == "archive");
}

TEST_CASE("singleFileName falls back to the archive name without its suffix") {
    std::vector<std::byte> data(10, std::byte{'z'});
    auto zstd = test::zstdCompress(data, 20);
    CHECK(nameFor("x/notes.txt.zst", zstd, Compression::Zstd) == "notes.txt");
    CHECK(nameFor("x/blob.bin", zstd, Compression::Zstd) == "blob.bin.out");
    CHECK(nameFor(".zst", zstd, Compression::Zstd) == ".zst.out");
    CHECK(gzipNamed("plain", "") == "plain.out");
}
