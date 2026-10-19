#include "formats/xz/stream.hpp"

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

// NOTE: produced by system xz 5.8 (`xz -6` of golden.txt holding "hello xz\n").
constexpr std::array<std::uint8_t, 76> goldenXz{
    0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0, 0x0d, 0x09,
    0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5f, 0x4f, 0x33, 0xe4,
    0x01, 0x00, 0x08, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x78, 0x7a, 0x0a, 0x00, 0x00, 0x00, 0x00,
    0xc1, 0x49, 0x3a, 0xfa, 0x63, 0x52, 0x14, 0x5a, 0x00, 0x01, 0x29, 0x09, 0x64, 0x92, 0x1c, 0x1d,
    0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
};

Bytes golden() {
    Bytes out;
    out.reserve(goldenXz.size());
    for (auto value : goldenXz) {
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
    return test::xzCompress(std::as_bytes(std::span(text.data(), text.size())));
}

Result<std::string> decode(const Bytes& bytes, const xz::Limits& limits = {}) {
    test::TempFile temp(bytes);
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);

    auto stream = xz::Stream::open(std::move(*file), limits);
    if (!stream) {
        return std::unexpected(stream.error());
    }

    std::string output;
    std::vector<std::byte> buffer(1000);
    while (true) {
        auto count = stream->read(buffer);
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            CHECK(stream->outputBytes() == output.size());
            return output;
        }
        output.append(reinterpret_cast<const char*>(buffer.data()), *count);
    }
}

ErrorKind rejected(const Bytes& bytes, const xz::Limits& limits = {}) {
    auto decoded = decode(bytes, limits);
    REQUIRE_FALSE(decoded);
    return decoded.error().kind;
}

}

TEST_CASE("xz stream reads a golden system-xz file one byte at a time") {
    auto bytes = golden();
    CHECK(xz::looksLikeXz(bytes));

    test::TempFile temp(bytes);
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    auto stream = xz::Stream::open(std::move(*file));
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

    CHECK_FALSE(xz::looksLikeXz(std::span(bytes).first(5)));
    auto bad = bytes;
    bad[0] = std::byte{0xFC};
    CHECK_FALSE(xz::looksLikeXz(bad));
}

TEST_CASE("xz stream joins concatenated streams and skips zero padding") {
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

TEST_CASE("xz stream reports truncation at every cut") {
    auto text = patterned(20'000, 'a');
    auto frame = compress(text);
    REQUIRE(frame.size() > 100);

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

TEST_CASE("xz stream rejects hostile streams") {
    auto text = patterned(20'000, 'a');
    auto frame = compress(text);

    SUBCASE("payload corruption") {
        auto bad = frame;
        bad[bad.size() / 2] ^= std::byte{0x01};
        CHECK(rejected(bad) == ErrorKind::Integrity);
    }
    SUBCASE("not an xz stream at all") {
        auto bad = frame;
        bad[0] = std::byte{0x1f};
        auto decoded = decode(bad);
        REQUIRE_FALSE(decoded);
        CHECK(decoded.error().kind == ErrorKind::Malformed);
        CHECK(decoded.error().what == "not an xz stream");
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
            CHECK(decoded.error().what == "trailing data after xz stream");
        }
    }
    SUBCASE("memory cap below the dictionary") {
        xz::Limits roomy{.memLimitBytes = std::uint64_t{256} << 20};
        CHECK(decode(frame, roomy));
        CHECK(
            rejected(frame, {.memLimitBytes = std::uint64_t{1} << 20}) == ErrorKind::LimitExceeded
        );
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
