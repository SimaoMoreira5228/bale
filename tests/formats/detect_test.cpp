#include "formats/detect.hpp"

#include "codecs/codec_fixture.hpp"
#include "format/envelope.hpp"
#include "formats/tar/tar_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <string>
#include <vector>

using namespace bale;

namespace {

ArchiveFormat detectBytes(std::span<const std::byte> bytes) {
    test::TempFile archive(bytes);
    auto file = archive.open();
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
    CHECK(detectBytes(encodeSuperblock(superblock)) == ArchiveFormat{.container = Container::Bale});

    auto header = tarHeader();
    CHECK(detectBytes(header) == ArchiveFormat{.container = Container::Tar});

    std::array localHeader{std::byte{'P'}, std::byte{'K'}, std::byte{3}, std::byte{4}};
    CHECK(detectBytes(localHeader) == ArchiveFormat{.container = Container::Zip});

    CHECK(detectBytes(emptyZip(0)) == ArchiveFormat{.container = Container::Zip});
    CHECK(detectBytes(emptyZip(70000)) == ArchiveFormat{.container = Container::Zip});
}

TEST_CASE("detectFormat rejects lookalikes") {
    SUBCASE("tar and zip") {
        auto header = tarHeader();
        header[148] = std::byte{'7'};
        CHECK(detectBytes(header) == ArchiveFormat{});

        auto zipWithJunkAfter = emptyZip(0);
        zipWithJunkAfter.push_back(std::byte{0});
        CHECK(detectBytes(zipWithJunkAfter) == ArchiveFormat{});

        CHECK(detectBytes({}) == ArchiveFormat{});
    }

    SUBCASE("xz and bzip2") {
        CHECK_FALSE(xz::looksLikeXz({}));
        CHECK_FALSE(bzip2::looksLikeBzip2({}));

        std::array<std::byte, 5> shortXz{
            std::byte{0xFD},
            std::byte{0x37},
            std::byte{0x7A},
            std::byte{0x58},
            std::byte{0x5A},
        };
        CHECK_FALSE(xz::looksLikeXz(shortXz));

        std::array<std::byte, 4> badDigit{
            std::byte{'B'},
            std::byte{'Z'},
            std::byte{'h'},
            std::byte{'0'},
        };
        CHECK_FALSE(bzip2::looksLikeBzip2(badDigit));

        std::vector<std::byte> text(2000, std::byte{'t'});
        auto xz = test::xzCompress(text);
        xz[0] = std::byte{0x1F};
        CHECK(detectBytes(xz) == ArchiveFormat{});
    }
}

TEST_CASE("detectFormat looks one tar block into every compressed stream") {
    tar::test::HeaderSpec spec;
    spec.name = "inner.txt";
    tar::test::ArchiveBuilder builder;
    builder.entry(spec, std::string(3000, 'x')).zeros(2);
    const auto& tarBytes = builder.bytes();

    ArchiveFormat tarGz{.container = Container::Tar, .compression = Compression::Gzip};
    ArchiveFormat tarZst{.container = Container::Tar, .compression = Compression::Zstd};
    ArchiveFormat tarXz{.container = Container::Tar, .compression = Compression::Xz};
    ArchiveFormat tarBz2{.container = Container::Tar, .compression = Compression::Bzip2};
    ArchiveFormat gzipFile{.container = Container::SingleFile, .compression = Compression::Gzip};
    ArchiveFormat zstdFile{.container = Container::SingleFile, .compression = Compression::Zstd};
    ArchiveFormat xzFile{.container = Container::SingleFile, .compression = Compression::Xz};
    ArchiveFormat bz2File{.container = Container::SingleFile, .compression = Compression::Bzip2};
    CHECK(name(tarGz) == "tar.gz");
    CHECK(name(tarZst) == "tar.zst");
    CHECK(name(tarXz) == "tar.xz");
    CHECK(name(tarBz2) == "tar.bz2");
    CHECK(name(gzipFile) == "gzip");
    CHECK(name(zstdFile) == "zstd");
    CHECK(name(xzFile) == "xz");
    CHECK(name(bz2File) == "bzip2");

    CHECK(detectBytes(test::gzipMember(tarBytes)) == tarGz);
    CHECK(detectBytes(test::zstdCompress(tarBytes, 20)) == tarZst);
    CHECK(detectBytes(test::xzCompress(tarBytes)) == tarXz);
    CHECK(detectBytes(test::bzip2Compress(tarBytes)) == tarBz2);

    auto split = test::gzipMember(std::span(tarBytes).first(100));
    auto rest = test::gzipMember(std::span(tarBytes).subspan(100));
    split.insert(split.end(), rest.begin(), rest.end());
    CHECK(detectBytes(split) == tarGz);

    std::vector<std::byte> text(2000, std::byte{'t'});
    CHECK(detectBytes(test::gzipMember(text, "notes.txt")) == gzipFile);
    CHECK(detectBytes(test::zstdCompress(text, 20)) == zstdFile);
    CHECK(detectBytes(test::xzCompress(text)) == xzFile);
    CHECK(detectBytes(test::bzip2Compress(text)) == bz2File);
    CHECK(detectBytes(test::gzipMember(std::span(text).first(tar::blockSize))) == gzipFile);

    auto badChecksum = tarBytes;
    badChecksum[148] = std::byte{'7'};
    CHECK(detectBytes(test::gzipMember(badChecksum)) == gzipFile);

    auto truncated = test::gzipMember(tarBytes);
    truncated.resize(20);
    CHECK(detectBytes(truncated) == gzipFile);

    auto corrupt = test::zstdCompress(tarBytes, 20);
    corrupt.resize(8);
    CHECK(detectBytes(corrupt) == zstdFile);
}
