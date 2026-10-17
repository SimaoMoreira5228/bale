#include "formats/tar/header.hpp"

#include "formats/tar/tar_fixture.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

using namespace bale;
using namespace bale::test;

namespace {

std::vector<std::byte> bytesOf(std::string_view text) {
    std::vector<std::byte> bytes;
    for (char value : text) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    return bytes;
}

std::optional<ErrorKind> paxError(std::string_view data, const TarLimits& limits = {}) {
    TarPaxValues values;
    auto parsed = parsePaxRecords(data, 0, limits, values);
    if (parsed) {
        return std::nullopt;
    }
    return parsed.error().kind;
}

}

TEST_CASE("Tar numeric fields accept octal terminators and base-256, reject garbage") {
    using namespace std::string_view_literals;

    CHECK(parseTarNumber(bytesOf("0000644\0"sv), 0) == 0644);
    CHECK(parseTarNumber(bytesOf("   644 \0"sv), 0) == 0644);
    CHECK(parseTarNumber(bytesOf("00000001234 "sv), 0) == 01234);
    CHECK(parseTarNumber(bytesOf("777777777777"sv), 0) == 0777777777777);
    CHECK(parseTarNumber(bytesOf("\0\0\0\0\0\0\0\0"sv), 0) == 0);
    CHECK(parseTarNumber(bytesOf("        "sv), 0) == 0);

    CHECK(parseTarNumber(bytesOf("0012 4\0"sv), 7).error().kind == ErrorKind::Malformed);
    CHECK(parseTarNumber(bytesOf("0012 4\0"sv), 7).error().offset == 7);
    CHECK(parseTarNumber(bytesOf("0000008\0"sv), 0).error().kind == ErrorKind::Malformed);
    CHECK(parseTarNumber(bytesOf("-000001\0"sv), 0).error().kind == ErrorKind::Malformed);
    CHECK(parseTarNumber(bytesOf(std::string(23, '7')), 0).error().kind == ErrorKind::Malformed);
    CHECK(parseTarNumber(bytesOf(std::string(22, '7')), 0).error().kind == ErrorKind::Malformed);
    CHECK(parseTarNumber(bytesOf("1" + std::string(21, '7')), 0) == UINT64_MAX);

    std::array<std::byte, 12> field{};
    field[0] = std::byte{0x80};
    field[10] = std::byte{0x01};
    CHECK(parseTarNumber(field, 0) == 256);

    field.fill(std::byte{0xFF});
    field[0] = std::byte{0x80};
    field[1] = std::byte{0};
    field[2] = std::byte{0};
    field[3] = std::byte{0};
    CHECK(parseTarNumber(field, 0) == UINT64_MAX);

    field[3] = std::byte{0x01};
    CHECK(parseTarNumber(field, 0).error().kind == ErrorKind::Malformed);

    field.fill(std::byte{0xFF});
    CHECK(parseTarNumber(field, 0).error().kind == ErrorKind::Malformed);
}

TEST_CASE("Tar header parsing validates the checksum and detects ustar, GNU and v7") {
    HeaderSpec spec;
    spec.name = "file.txt";
    spec.prefix = "some/dir";
    spec.size = 1234;
    spec.mtime = 1700000000;
    spec.uid = 1000;
    auto block = makeHeader(spec);

    auto header = parseTarHeader(block, 0);
    REQUIRE(header);
    CHECK(header->format == TarFormat::Ustar);
    CHECK(header->name == "file.txt");
    CHECK(header->prefix == "some/dir");
    CHECK(header->uname == "user");
    CHECK(header->size == 1234);
    CHECK(header->mtime == 1700000000);
    CHECK(header->uid == 1000);
    CHECK(header->mode == 0644);
    CHECK(looksLikeTar(block));

    auto corrupted = block;
    corrupted[3] ^= std::byte{0x20};
    CHECK(parseTarHeader(corrupted, 1024).error().kind == ErrorKind::Integrity);
    CHECK(parseTarHeader(corrupted, 1024).error().offset == 1024);
    CHECK_FALSE(looksLikeTar(corrupted));

    auto badMagic = block;
    putText(badMagic, 257, "pkzip");
    sealChecksum(badMagic);
    CHECK(parseTarHeader(badMagic, 0).error().kind == ErrorKind::Malformed);
    CHECK_FALSE(looksLikeTar(badMagic));

    spec.magic = gnuMagic;
    auto gnu = makeHeader(spec);
    REQUIRE(parseTarHeader(gnu, 0));
    CHECK(parseTarHeader(gnu, 0)->format == TarFormat::Gnu);
    CHECK(parseTarHeader(gnu, 0)->prefix.empty());

    spec.magic = v7Magic;
    auto v7 = makeHeader(spec);
    REQUIRE(parseTarHeader(v7, 0));
    CHECK(parseTarHeader(v7, 0)->format == TarFormat::V7);
    CHECK(parseTarHeader(v7, 0)->uname.empty());
    CHECK(looksLikeTar(v7));

    Block zero{};
    CHECK_FALSE(looksLikeTar(zero));
    CHECK(parseTarHeader(zero, 0).error().kind == ErrorKind::Integrity);
}

TEST_CASE("Tar header checksum accepts the historic signed sum") {
    HeaderSpec spec;
    spec.name = "caf\xE9\xE9\xE9";
    auto block = makeHeader(spec);

    std::fill_n(block.begin() + 148, 8, std::byte{' '});
    std::int64_t signedSum = 0;
    for (auto byte : block) {
        signedSum += static_cast<std::int8_t>(std::to_integer<std::uint8_t>(byte));
    }
    putOctal(block, 148, 7, static_cast<std::uint64_t>(signedSum));

    auto header = parseTarHeader(block, 0);
    REQUIRE(header);
    CHECK(header->name == "caf\xE9\xE9\xE9");

    putOctal(block, 148, 7, static_cast<std::uint64_t>(signedSum) + 1);
    CHECK(parseTarHeader(block, 0).error().kind == ErrorKind::Integrity);
}

TEST_CASE("Tar device numbers are parsed only for device entries") {
    HeaderSpec spec;
    spec.name = "dev/null";
    spec.typeflag = '3';
    auto block = makeHeader(spec);
    putOctal(block, 329, 8, 1);
    putOctal(block, 337, 8, 3);
    sealChecksum(block);

    auto header = parseTarHeader(block, 0);
    REQUIRE(header);
    CHECK(header->devMajor == 1);
    CHECK(header->devMinor == 3);

    block[156] = std::byte{'0'};
    putText(block, 329, "garbage!");
    sealChecksum(block);
    CHECK(parseTarHeader(block, 0));

    block[156] = std::byte{'4'};
    sealChecksum(block);
    CHECK(parseTarHeader(block, 0).error().offset == 329);
}

TEST_CASE("pax records apply known keys including fractional and negative mtime") {
    TarLimits limits;
    TarPaxValues values;
    auto data = paxRecord("path", "a/b/c") + paxRecord("size", "18446744073709551615") +
        paxRecord("mtime", "-1.25") + paxRecord("uid", "4294967296") +
        paxRecord("SCHILY.xattr.user.k", "ignored") + paxRecord("gname", "staff");
    REQUIRE(parsePaxRecords(data, 0, limits, values));
    CHECK(values.path == "a/b/c");
    CHECK(values.size == UINT64_MAX);
    CHECK(values.mtimeSeconds == -2);
    CHECK(values.mtimeNanoseconds == 750'000'000);
    CHECK(values.uid == 4294967296);
    CHECK(values.gname == "staff");
    CHECK_FALSE(values.hasGid);

    auto more = paxRecord("mtime", "1700000000.1234567891") + paxRecord("path", "");
    REQUIRE(parsePaxRecords(more, 0, limits, values));
    CHECK(values.mtimeSeconds == 1700000000);
    CHECK(values.mtimeNanoseconds == 123'456'789);
    CHECK_FALSE(values.hasPath);
}

TEST_CASE("pax record framing is strict") {
    using namespace std::string_view_literals;

    CHECK(paxError("6 a=b\n") == std::nullopt);
    CHECK(paxError("7 a=b\n") == ErrorKind::Malformed);
    CHECK(paxError("5 a=b\n") == ErrorKind::Malformed);
    CHECK(paxError("6 a=bX") == ErrorKind::Malformed);
    CHECK(paxError("6 =bb\n") == ErrorKind::Malformed);
    CHECK(paxError("6 abc\n") == ErrorKind::Malformed);
    CHECK(paxError("6a=bc\n") == ErrorKind::Malformed);
    CHECK(paxError(" 6 a=b\n") == ErrorKind::Malformed);
    CHECK(paxError("3 \n") == ErrorKind::Malformed);
    CHECK(paxError("0 a=b\n") == ErrorKind::Malformed);
    CHECK(paxError("6 a=b\n6 a=") == ErrorKind::Malformed);
    CHECK(paxError("12345678901234567890 a=b\n") == ErrorKind::Malformed);
    CHECK(paxError("6 a=b\n\0\0\0"sv) == ErrorKind::Malformed);

    CHECK(paxError(paxRecord("size", "12x")) == ErrorKind::Malformed);
    CHECK(paxError(paxRecord("size", "18446744073709551616")) == ErrorKind::Malformed);
    CHECK(paxError(paxRecord("mtime", "1.")) == ErrorKind::Malformed);
    CHECK(paxError(paxRecord("mtime", "9223372036854775808")) == ErrorKind::Malformed);
    CHECK(paxError(paxRecord("path", "a\0b"sv)) == ErrorKind::Malformed);
    CHECK(paxError(paxRecord("linkpath", "a\0b"sv)) == ErrorKind::Malformed);
    CHECK(paxError(paxRecord("GNU.sparse.major", "1")) == ErrorKind::Unsupported);

    TarLimits limits;
    limits.maxPathBytes = 8;
    CHECK(paxError(paxRecord("path", "12345678"), limits) == std::nullopt);
    CHECK(paxError(paxRecord("path", "123456789"), limits) == ErrorKind::LimitExceeded);

    TarPaxValues values;
    auto parsed = parsePaxRecords("6 a=b\n7 a=b\n", 1000, {}, values);
    REQUIRE_FALSE(parsed);
    CHECK(parsed.error().offset == 1006);
}

TEST_CASE("Tar padded size rounds to blocks and detects overflow") {
    CHECK(tarPaddedSize(0) == 0);
    CHECK(tarPaddedSize(1) == 512);
    CHECK(tarPaddedSize(512) == 512);
    CHECK(tarPaddedSize(UINT64_MAX - 511) == UINT64_MAX - 511);
    CHECK(tarPaddedSize(UINT64_MAX - 510) == std::nullopt);
}
