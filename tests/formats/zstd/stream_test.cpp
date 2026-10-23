#include "formats/zstd/stream.hpp"

#include "base/endian.hpp"
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

std::string patterned(std::size_t size, char seed) {
    std::string text(size, '.');
    for (std::size_t index = 0; index < text.size(); index += 37) {
        text[index] = static_cast<char>(seed + static_cast<char>(index % 23));
    }
    return text;
}

Bytes compress(std::string_view text, int windowLog = 20) {
    return test::zstdCompress(std::as_bytes(std::span(text.data(), text.size())), windowLog);
}

Bytes skippableFrame(std::size_t payload) {
    Bytes out(8 + payload, std::byte{0xEE});
    storeLe(out.data(), std::uint32_t{0x184D2A53});
    storeLe(out.data() + 4, static_cast<std::uint32_t>(payload));
    return out;
}

void append(Bytes& out, const Bytes& more) {
    out.insert(out.end(), more.begin(), more.end());
}

Result<std::string> decode(const Bytes& bytes, const zstd::Limits& limits = {}) {
    test::TempFile temp(bytes);
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);

    auto stream = zstd::Stream::open(std::move(*file), limits);
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

ErrorKind rejected(const Bytes& bytes, const zstd::Limits& limits = {}) {
    auto decoded = decode(bytes, limits);
    REQUIRE_FALSE(decoded);
    return decoded.error().kind;
}

}

TEST_CASE("zstd stream joins frames, skips skippable frames and refills small chunks") {
    auto first = patterned(150'000, 'a');
    auto second = patterned(3000, 'K');

    auto bytes = skippableFrame(5);
    append(bytes, compress(first));
    append(bytes, skippableFrame(0));
    append(bytes, compress(second));
    CHECK_FALSE(zstd::looksLikeZstd(bytes));
    CHECK(zstd::looksLikeZstd(compress(second)));

    auto decoded = decode(bytes, {.chunkBytes = 100});
    REQUIRE(decoded);
    CHECK(*decoded == first + second);

    auto empty = decode(compress(""));
    REQUIRE(empty);
    CHECK(empty->empty());
}

TEST_CASE("zstd stream reports truncation at every structure boundary") {
    auto text = patterned(20'000, 'a');
    auto frame = compress(text);
    REQUIRE(frame.size() > 100);

    for (std::size_t cut :
         {std::size_t{0},
          std::size_t{3},
          std::size_t{4},
          std::size_t{9},
          frame.size() / 2,
          frame.size() - 4,
          frame.size() - 1}) {
        CAPTURE(cut);
        Bytes truncated(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(cut));
        CHECK(rejected(truncated) == ErrorKind::Truncated);
    }

    auto twoFrames = frame;
    append(twoFrames, Bytes(frame.begin(), frame.begin() + 6));
    CHECK(rejected(twoFrames) == ErrorKind::Truncated);
}

TEST_CASE("zstd stream rejects hostile frames") {
    auto text = patterned(20'000, 'a');
    auto frame = compress(text);

    SUBCASE("content checksum mismatch") {
        frame.back() ^= std::byte{0x01};
        CHECK(rejected(frame) == ErrorKind::Integrity);
    }
    SUBCASE("trailing garbage after the last frame") {
        frame.push_back(std::byte{'P'});
        frame.push_back(std::byte{'K'});
        frame.push_back(std::byte{3});
        frame.push_back(std::byte{4});
        CHECK(rejected(frame) == ErrorKind::Malformed);
    }
    SUBCASE("not a zstd frame at all") {
        frame[0] = std::byte{0x29};
        auto decoded = decode(frame);
        REQUIRE_FALSE(decoded);
        CHECK(decoded.error().what == "not a zstd frame");
    }
    SUBCASE("window larger than the limit") {
        auto wide = compress(text, 24);
        CHECK(decode(wide, {.maxWindowLog = 24}));
        CHECK(rejected(wide, {.maxWindowLog = 20}) == ErrorKind::LimitExceeded);
    }
    SUBCASE("output budget") {
        CHECK(decode(frame, {.maxOutputBytes = text.size()}));
        CHECK(rejected(frame, {.maxOutputBytes = text.size() - 1}) == ErrorKind::LimitExceeded);
    }
}
