#include "formats/gzip/decoder.hpp"

#include "base/endian.hpp"
#include "codecs/codec_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace bale;

namespace {

using Bytes = std::vector<std::byte>;

// NOTE: produced by GNU gzip 1.14 (`gzip -9` of hello.txt containing "hello gzip\n").
constexpr std::array<std::uint8_t, 41> goldenGzip{
    0x1f, 0x8b, 0x08, 0x08, 0xa5, 0x35, 0x57, 0x69, 0x02, 0x03, 0x68, 0x65, 0x6c, 0x6c,
    0x6f, 0x2e, 0x74, 0x78, 0x74, 0x00, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x48, 0xaf,
    0xca, 0x2c, 0xe0, 0x02, 0x00, 0x39, 0x7c, 0x63, 0x56, 0x0b, 0x00, 0x00, 0x00,
};

Bytes golden() {
    Bytes out;
    out.reserve(goldenGzip.size());
    for (auto value : goldenGzip) {
        out.push_back(std::byte{value});
    }
    return out;
}

void append(Bytes& out, std::string_view text) {
    for (char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
}

void append32(Bytes& out, std::uint32_t value) {
    std::array<std::byte, 4> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

struct MemberSpec {
    std::string data{};
    std::uint8_t flags = 0;
    std::uint8_t method = 8;
    std::string name{};
    std::string comment{};
    Bytes extra{};
    std::optional<std::uint16_t> headerCrc{};
    std::optional<std::uint32_t> crc{};
    std::optional<std::uint32_t> isize{};
};

Bytes buildMember(const MemberSpec& spec) {
    Bytes out{std::byte{0x1f}, std::byte{0x8b}, std::byte{spec.method}, std::byte{spec.flags}};
    append32(out, 1'700'000'000);
    out.push_back(std::byte{0});
    out.push_back(std::byte{3});
    if ((spec.flags & gzip::flagExtra) != 0) {
        out.push_back(static_cast<std::byte>(spec.extra.size() & 0xFF));
        out.push_back(static_cast<std::byte>(spec.extra.size() >> 8));
        out.insert(out.end(), spec.extra.begin(), spec.extra.end());
    }
    if ((spec.flags & gzip::flagName) != 0) {
        append(out, spec.name);
        out.push_back(std::byte{0});
    }
    if ((spec.flags & gzip::flagComment) != 0) {
        append(out, spec.comment);
        out.push_back(std::byte{0});
    }
    if ((spec.flags & gzip::flagHeaderCrc) != 0) {
        auto crc = spec.headerCrc.value_or(static_cast<std::uint16_t>(Crc32::of(out) & 0xFFFF));
        out.push_back(static_cast<std::byte>(crc & 0xFF));
        out.push_back(static_cast<std::byte>(crc >> 8));
    }

    auto data = std::as_bytes(std::span(spec.data.data(), spec.data.size()));
    auto packed = test::deflateRaw(data);
    out.insert(out.end(), packed.begin(), packed.end());
    append32(out, spec.crc.value_or(Crc32::of(data)));
    append32(out, spec.isize.value_or(static_cast<std::uint32_t>(spec.data.size())));
    return out;
}

MemberSpec fullHeaderSpec(std::string data) {
    return MemberSpec{
        .data = std::move(data),
        .flags = gzip::flagText | gzip::flagHeaderCrc | gzip::flagExtra | gzip::flagName |
            gzip::flagComment,
        .name = "report.txt",
        .comment = "made by the bale tests",
        .extra = {
            std::byte{'B'},
            std::byte{'L'},
            std::byte{2},
            std::byte{0},
            std::byte{7},
            std::byte{9}
        },
    };
}

struct Decoded {
    std::string output;
    Result<gzip::Summary> summary = gzip::Summary{};
};

Decoded decodeBytes(const Bytes& bytes, const gzip::Limits& limits = {}) {
    Decoded decoded;
    test::TempFile temp(bytes);
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);

    auto decoder = gzip::Decoder::open(std::move(*file), limits);
    if (!decoder) {
        decoded.summary = std::unexpected(decoder.error());
        return decoded;
    }
    decoded.summary = decoder->decode([&](std::span<const std::byte> chunk) {
        decoded.output.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    return decoded;
}

void checkRejected(
    const Bytes& bytes,
    ErrorKind kind,
    std::string_view what,
    const gzip::Limits& limits = {}
) {
    auto decoded = decodeBytes(bytes, limits);
    REQUIRE_FALSE(decoded.summary);
    CHECK(decoded.summary.error().kind == kind);
    CHECK(decoded.summary.error().what == what);
}

std::string patterned(std::size_t size) {
    std::string text(size, '.');
    for (std::size_t index = 0; index < text.size(); index += 53) {
        text[index] = static_cast<char>('a' + index % 26);
    }
    return text;
}

}

TEST_CASE("gzip decoder reads a golden GNU gzip member and its header") {
    auto bytes = golden();
    CHECK(gzip::looksLikeGzip(bytes));

    test::TempFile temp(bytes);
    auto file = temp.open();
    REQUIRE(file);
    auto decoder = gzip::Decoder::open(std::move(*file));
    REQUIRE(decoder);
    CHECK(decoder->header().name == "hello.txt");
    CHECK(decoder->header().comment.empty());
    CHECK(decoder->header().mtime == 0x695735a5);
    CHECK(decoder->header().extraFlags == 2);
    CHECK(decoder->header().os == 3);
    CHECK(decoder->header().size == 20);

    std::string output;
    auto summary = decoder->decode([&](std::span<const std::byte> chunk) {
        output.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    REQUIRE(summary);
    CHECK(output == "hello gzip\n");
    CHECK(summary->members == 1);
    CHECK(summary->outputBytes == 11);

    auto again = decoder->decode([](std::span<const std::byte>) {
        return Result<void>{};
    });
    REQUIRE(again);
    CHECK(again->outputBytes == 11);

    CHECK_FALSE(gzip::looksLikeGzip(std::span(bytes).first(9)));
    auto reserved = bytes;
    reserved[3] = std::byte{0x28};
    CHECK_FALSE(gzip::looksLikeGzip(reserved));
}

TEST_CASE("gzip decoder concatenates members and accepts only zero padding after them") {
    auto large = patterned(200'000);
    auto bytes = golden();
    auto second = buildMember(fullHeaderSpec(large));
    bytes.insert(bytes.end(), second.begin(), second.end());

    auto padded = bytes;
    padded.resize(padded.size() + 300, std::byte{0});
    auto decoded = decodeBytes(padded, {.chunkBytes = 1000});
    REQUIRE(decoded.summary);
    CHECK(decoded.output == "hello gzip\n" + large);
    CHECK(decoded.summary->members == 2);
    CHECK(decoded.summary->outputBytes == large.size() + 11);

    SUBCASE("garbage after the padding") {
        append(padded, "x");
        checkRejected(padded, ErrorKind::Malformed, "trailing garbage after gzip member");
    }
    SUBCASE("garbage right after a member") {
        append(bytes, "PK");
        checkRejected(bytes, ErrorKind::Malformed, "trailing garbage after gzip member");
    }
    SUBCASE("a cut-off magic of a further member") {
        bytes.push_back(std::byte{0x1f});
        bytes.push_back(std::byte{0x8b});
        checkRejected(bytes, ErrorKind::Truncated, "gzip header truncated");
    }
    SUBCASE("a later member with a bad size") {
        auto spec = fullHeaderSpec("tail");
        spec.isize = 5;
        auto bad = buildMember(spec);
        bytes.insert(bytes.end(), bad.begin(), bad.end());
        checkRejected(bytes, ErrorKind::Integrity, "gzip member size mismatch");
    }
}

TEST_CASE("gzip header parser enforces flags, method, checksum and limits") {
    auto valid = buildMember(fullHeaderSpec("body"));
    auto header = gzip::parseHeader(valid, {});
    REQUIRE(header);
    CHECK(header->name == "report.txt");
    CHECK(header->comment == "made by the bale tests");
    CHECK(header->extra.size() == 6);
    CHECK(header->text());
    CHECK(header->mtime == 1'700'000'000);
    CHECK(decodeBytes(valid, {.maxExtraBytes = 6, .maxNameLength = 10, .maxCommentLength = 22})
              .summary);

    SUBCASE("header CRC-16 mismatch") {
        auto spec = fullHeaderSpec("body");
        spec.headerCrc = 0xBEEF;
        checkRejected(buildMember(spec), ErrorKind::Integrity, "gzip header CRC-16 mismatch");
    }
    SUBCASE("reserved flag bit") {
        auto spec = fullHeaderSpec("body");
        spec.flags |= 0x40;
        checkRejected(buildMember(spec), ErrorKind::Malformed, "reserved gzip flag bits set");
    }
    SUBCASE("method other than deflate") {
        auto spec = fullHeaderSpec("body");
        spec.method = 7;
        checkRejected(
            buildMember(spec),
            ErrorKind::Unsupported,
            "gzip compression method is not deflate"
        );
    }
    SUBCASE("limits one below the actual fields") {
        checkRejected(
            valid,
            ErrorKind::LimitExceeded,
            "gzip extra field exceeds limit",
            {.maxExtraBytes = 5}
        );
        checkRejected(
            valid,
            ErrorKind::LimitExceeded,
            "gzip file name exceeds limit",
            {.maxNameLength = 9}
        );
        checkRejected(
            valid,
            ErrorKind::LimitExceeded,
            "gzip comment exceeds limit",
            {.maxCommentLength = 21}
        );
    }
    SUBCASE("truncation at every length") {
        for (std::size_t length = 0; length < valid.size(); ++length) {
            Bytes truncated(valid.begin(), valid.begin() + static_cast<std::ptrdiff_t>(length));
            auto decoded = decodeBytes(truncated);
            REQUIRE_FALSE(decoded.summary);
            CHECK(decoded.summary.error().kind == ErrorKind::Truncated);
        }
    }
}

TEST_CASE("gzip decoder verifies the trailer and stops at the output budget") {
    auto text = patterned(5000);

    SUBCASE("CRC-32 mismatch") {
        checkRejected(
            buildMember({.data = text, .crc = 0}),
            ErrorKind::Integrity,
            "gzip member CRC-32 mismatch"
        );
    }
    SUBCASE("ISIZE mismatch") {
        checkRejected(
            buildMember({.data = text, .isize = 4999}),
            ErrorKind::Integrity,
            "gzip member size mismatch"
        );
    }
    SUBCASE("corrupt deflate data") {
        auto bytes = buildMember({.data = text});
        bytes[gzip::fixedHeaderSize] = std::byte{0x07};
        checkRejected(bytes, ErrorKind::Malformed, "invalid deflate stream");
    }
    SUBCASE("output budget") {
        auto bytes = buildMember({.data = text});
        CHECK(decodeBytes(bytes, {.maxOutputBytes = 5000, .chunkBytes = 512}).summary);

        auto decoded = decodeBytes(bytes, {.maxOutputBytes = 4999, .chunkBytes = 512});
        REQUIRE_FALSE(decoded.summary);
        CHECK(decoded.summary.error().kind == ErrorKind::LimitExceeded);
        CHECK(decoded.summary.error().what == "gzip output exceeds limit");
        CHECK(decoded.output == text.substr(0, 4999));
    }
}
