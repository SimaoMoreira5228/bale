#include "formats/detect.hpp"

#include "format/envelope.hpp"
#include "formats/tar/tar_fixture.hpp"

#include <doctest/doctest.h>

#include <array>
#include <vector>

using namespace bale;

namespace {

ArchiveFormat detectBytes(std::span<const std::byte> bytes) {
    tar::test::TempArchive archive;
    auto file = archive.write(bytes);
    REQUIRE(file);

    auto format = detectFormat(*file);
    REQUIRE(format);
    return *format;
}

tar::test::BlockBytes tarHeader() {
    tar::test::HeaderSpec spec;
    spec.name = "a.txt";
    return tar::test::makeHeader(spec);
}

std::vector<std::byte> emptyZip(std::size_t prefixBytes) {
    std::vector<std::byte> bytes(prefixBytes, std::byte{'#'});
    bytes.push_back(std::byte{'P'});
    bytes.push_back(std::byte{'K'});
    bytes.push_back(std::byte{5});
    bytes.push_back(std::byte{6});
    bytes.resize(bytes.size() + 18);
    return bytes;
}

}

TEST_CASE("detectFormat recognizes each format by structure, not extension") {
    Superblock superblock;
    CHECK(detectBytes(encodeSuperblock(superblock)) == ArchiveFormat::Bale);

    auto header = tarHeader();
    CHECK(detectBytes(header) == ArchiveFormat::Tar);

    std::array localHeader{std::byte{'P'}, std::byte{'K'}, std::byte{3}, std::byte{4}};
    CHECK(detectBytes(localHeader) == ArchiveFormat::Zip);

    CHECK(detectBytes(emptyZip(0)) == ArchiveFormat::Zip);
    CHECK(detectBytes(emptyZip(70000)) == ArchiveFormat::Zip);
}

TEST_CASE("detectFormat rejects lookalikes") {
    auto header = tarHeader();
    header[148] = std::byte{'7'};
    CHECK(detectBytes(header) == ArchiveFormat::Unknown);

    auto zipWithJunkAfter = emptyZip(0);
    zipWithJunkAfter.push_back(std::byte{0});
    CHECK(detectBytes(zipWithJunkAfter) == ArchiveFormat::Unknown);

    CHECK(detectBytes({}) == ArchiveFormat::Unknown);
}
