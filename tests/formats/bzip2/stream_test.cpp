#include "formats/bzip2/stream.hpp"

#include "codecs/codec_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace bale;

namespace {

using Bytes = std::vector<std::byte>;

// NOTE: produced by system bzip2 1.0.8 (`bzip2 -9` of golden.txt holding "hello xz\n").
constexpr std::array<std::uint8_t, 49> goldenBz2{
    0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x1e, 0x14, 0x39,
    0xba, 0x00, 0x00, 0x01, 0xd1, 0x80, 0x00, 0x10, 0x40, 0x00, 0x02, 0x44, 0x80,
    0x50, 0x20, 0x00, 0x31, 0x0c, 0x08, 0x20, 0x33, 0x49, 0x07, 0xcc, 0xa2, 0x78,
    0xbb, 0x92, 0x29, 0xc2, 0x84, 0x80, 0xf0, 0xa1, 0xcd, 0xd0,
};

Bytes golden() {
    Bytes out;
    out.reserve(goldenBz2.size());
    for (auto value : goldenBz2) {
        out.push_back(std::byte{value});
    }
    return out;
}

std::string patterned(std::size_t size, char seed) {
    std::string text(size, '.');
    for (std::size_t index = 0; index < text.size(); index += 37) {
        text[index] = static_cast<char>(seed + static_cast<char>(index % 23));
    }
    return text;
}

Bytes compress(std::string_view text) {
    return test::bzip2Compress(std::as_bytes(std::span(text.data(), text.size())));
}

Result<std::string> decode(const Bytes& bytes, const bzip2::Limits& limits = {}) {
    test::TempFile temp(bytes);
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);

    auto stream = bzip2::Stream::open(std::move(*file), limits);
    if (!stream) {
        return tl::unexpected<Error>(stream.error());
    }

    std::string output;
    std::vector<std::byte> buffer(1000);
    while (true) {
        auto count = stream->read(buffer);
        if (!count) {
            return tl::unexpected<Error>(count.error());
        }
        if (*count == 0) {
            CHECK(stream->outputBytes() == output.size());
            return output;
        }
        output.append(reinterpret_cast<const char*>(buffer.data()), *count);
    }
}

ErrorKind rejected(const Bytes& bytes, const bzip2::Limits& limits = {}) {
    auto decoded = decode(bytes, limits);
    REQUIRE_FALSE(decoded);
    return decoded.error().kind;
}

}

TEST_CASE("bzip2 stream reads a golden system-bzip2 file one byte at a time") {
    auto bytes = golden();
    CHECK(bzip2::looksLikeBzip2(bytes));

    test::TempFile temp(bytes);
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    auto stream = bzip2::Stream::open(std::move(*file));
    REQUIRE(stream);
    CHECK(stream->streams() == 1);

    std::string output;
    std::array<std::byte, 1> one{};
    while (true) {
        auto count = stream->read(one);
        REQUIRE(count);
        if (*count == 0) {
            break;
        }
        output.push_back(static_cast<char>(one[0]));
    }
    CHECK(output == "hello xz\n");
    CHECK(stream->outputBytes() == 9);
    CHECK(stream->streams() == 1);

    std::array<std::byte, 4> after{};
    CHECK(stream->read(after) == 0);
    CHECK(stream->read(std::span<std::byte>{}).error().kind == ErrorKind::LimitExceeded);

    CHECK_FALSE(bzip2::looksLikeBzip2(std::span(bytes).first(3)));
    auto badDigit = bytes;
    badDigit[3] = std::byte{'0'};
    CHECK_FALSE(bzip2::looksLikeBzip2(badDigit));
    auto badMagic = bytes;
    badMagic[0] = std::byte{'X'};
    CHECK_FALSE(bzip2::looksLikeBzip2(badMagic));
}

TEST_CASE("bzip2 stream joins concatenated streams and skips zero padding") {
    auto first = patterned(150'000, 'a');
    auto second = patterned(3000, 'K');

    auto bytes = compress(first);
    auto rest = compress(second);
    bytes.insert(bytes.end(), rest.begin(), rest.end());
    bytes.resize(bytes.size() + 64, std::byte{0});

    auto decoded = decode(bytes, {.chunkBytes = 100});
    REQUIRE(decoded);
    CHECK(*decoded == first + second);

    auto empty = decode(compress(""));
    REQUIRE(empty);
    CHECK(empty->empty());
}

TEST_CASE("bzip2 stream reports truncation at every cut") {
    auto text = patterned(20'000, 'a');
    auto frame = compress(text);
    REQUIRE(frame.size() > 10);

    for (std::size_t cut = 0; cut < frame.size(); ++cut) {
        CAPTURE(cut);
        Bytes truncated(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(cut));
        CHECK(rejected(truncated) == ErrorKind::Truncated);
    }

    auto twoStreams = frame;
    auto rest = compress(text);
    twoStreams.insert(twoStreams.end(), rest.begin(), rest.end());
    Bytes cutSecond(
        twoStreams.begin(),
        twoStreams.begin() + static_cast<std::ptrdiff_t>(frame.size() + 10)
    );
    CHECK(rejected(cutSecond) == ErrorKind::Truncated);
}

TEST_CASE("bzip2 stream rejects hostile streams") {
    auto text = patterned(20'000, 'a');
    auto frame = compress(text);

    SUBCASE("block payload corruption") {
        auto bad = frame;
        bad[bad.size() / 2] ^= std::byte{0x01};
        CHECK(rejected(bad) == ErrorKind::Integrity);
    }
    SUBCASE("not a bzip2 stream at all") {
        auto bad = frame;
        bad[0] = std::byte{'X'};
        auto decoded = decode(bad);
        REQUIRE_FALSE(decoded);
        CHECK(decoded.error().kind == ErrorKind::Malformed);
        CHECK(decoded.error().what == "not a bzip2 stream");
    }
    SUBCASE("trailing garbage after the last stream") {
        for (std::string garbage : {std::string("X"), std::string("GARBAGE!")}) {
            CAPTURE(garbage);
            auto bad = frame;
            for (char value : garbage) {
                bad.push_back(static_cast<std::byte>(value));
            }
            auto decoded = decode(bad);
            REQUIRE_FALSE(decoded);
            CHECK(decoded.error().kind == ErrorKind::Malformed);
            CHECK(decoded.error().what == "trailing data after bzip2 stream");
        }
    }
    SUBCASE("output budget") {
        CHECK(decode(frame, {.maxOutputBytes = text.size()}));
        CHECK(rejected(frame, {.maxOutputBytes = text.size() - 1}) == ErrorKind::LimitExceeded);
    }
    SUBCASE("zero chunk size") {
        auto decoded = decode(frame, {.chunkBytes = 0});
        REQUIRE_FALSE(decoded);
        CHECK(decoded.error().kind == ErrorKind::LimitExceeded);
    }
}
