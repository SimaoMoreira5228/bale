#include "codecs/decoders.hpp"
#include "codecs/encoders.hpp"

#include "codecs/codec_fixture.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <vector>

using namespace bale;

namespace {

using Bytes = std::vector<std::byte>;

template <std::size_t N> Bytes bytesOf(const std::array<std::uint8_t, N>& raw) {
    Bytes out;
    out.reserve(raw.size());
    for (auto value : raw) {
        out.push_back(std::byte{value});
    }
    return out;
}

std::span<const std::byte> asBytes(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

std::string_view asText(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

constexpr std::string_view goldenZstdText =
    "zstd golden vector, zstd golden vector, zstd golden vector\n";

// NOTE: produced by the zstd 1.5.7 CLI (`zstd -19` from a pipe): 8 MiB window, XXH64 checksum.
constexpr std::array<std::uint8_t, 40> goldenZstd{
    0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x68, 0xdd, 0x00, 0x00, 0xa8, 0x7a, 0x73, 0x74, 0x64,
    0x20, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72,
    0x2c, 0x20, 0x0a, 0x01, 0x00, 0xde, 0x33, 0x99, 0x34, 0x2e, 0xd5, 0x4e,
};

struct Drained {
    std::string output;
    std::size_t consumed = 0;
    bool finished = false;
    Error error{};
    bool failed = false;
};

template <typename Decoder>
Drained drain(
    Decoder& decoder,
    std::span<const std::byte> input,
    std::size_t inputStep,
    std::size_t outputStep
) {
    Drained drained;
    std::vector<std::byte> output(outputStep);
    while (true) {
        auto slice =
            input.subspan(drained.consumed, std::min(inputStep, input.size() - drained.consumed));
        auto step = decoder.decompress(slice, output);
        if (!step) {
            drained.error = step.error();
            drained.failed = true;
            return drained;
        }

        drained.consumed += step->consumed;
        drained.output.append(asText(std::span(output).first(step->produced)));
        if (step->finished) {
            drained.finished = true;
            return drained;
        }
        if (step->consumed == 0 && step->produced == 0 && drained.consumed == input.size()) {
            return drained;
        }
    }
}

}

TEST_CASE("Inflater decodes a golden raw DEFLATE vector in any step size and after reset") {
    auto inflater = Inflater::create();
    REQUIRE(inflater);
    auto golden = test::goldenDeflate();
    golden.push_back(std::byte{0xEE});

    auto tiny = drain(*inflater, golden, 1, 3);
    CHECK_FALSE(tiny.failed);
    CHECK(tiny.finished);
    CHECK(tiny.output == test::goldenDeflateText);
    CHECK(tiny.consumed == test::goldenDeflate().size());

    std::array<std::byte, 8> output{};
    auto after = inflater->decompress(golden, output);
    REQUIRE(after);
    CHECK(after->finished);
    CHECK(after->consumed == 0);
    CHECK(after->produced == 0);

    REQUIRE(inflater->reset());
    auto whole = drain(*inflater, golden, golden.size(), 4096);
    CHECK(whole.finished);
    CHECK(whole.output == test::goldenDeflateText);

    std::string large(300'000, 'q');
    for (std::size_t index = 0; index < large.size(); index += 97) {
        large[index] = static_cast<char>('a' + index % 26);
    }
    auto compressed = test::deflateRaw(large);
    REQUIRE_FALSE(compressed.empty());
    REQUIRE(inflater->reset());
    auto big = drain(*inflater, compressed, 4093, 65536);
    CHECK(big.finished);
    CHECK(big.output == large);
}

TEST_CASE("Inflater reports corrupt streams and stalls on truncated ones") {
    auto inflater = Inflater::create();
    REQUIRE(inflater);

    SUBCASE("reserved block type") {
        Bytes reserved{std::byte{0x07}, std::byte{0x00}};
        auto drained = drain(*inflater, reserved, reserved.size(), 64);
        REQUIRE(drained.failed);
        CHECK(drained.error.kind == ErrorKind::Malformed);
        CHECK(drained.error.what == "invalid deflate stream");
    }
    SUBCASE("distance reaching before the start of the output") {
        Bytes farBack{std::byte{0x03}, std::byte{0x02}, std::byte{0x00}};
        auto drained = drain(*inflater, farBack, farBack.size(), 64);
        REQUIRE(drained.failed);
        CHECK(drained.error.kind == ErrorKind::Malformed);
    }
    SUBCASE("truncation at every length never finishes") {
        auto golden = test::goldenDeflate();
        for (std::size_t length = 0; length < golden.size(); ++length) {
            REQUIRE(inflater->reset());
            auto drained = drain(*inflater, std::span(golden).first(length), 5, 16);
            CHECK_FALSE(drained.finished);
            CHECK_FALSE(drained.failed);
        }
    }
}

TEST_CASE("ZstdDecoder verifies checksums and enforces the caller window limit") {
    SUBCASE("golden frame, checksum and magic") {
        auto decoder = ZstdDecoder::create();
        REQUIRE(decoder);
        auto golden = bytesOf(goldenZstd);

        auto drained = drain(*decoder, golden, 3, 5);
        CHECK_FALSE(drained.failed);
        CHECK(drained.finished);
        CHECK(drained.output == goldenZstdText);

        auto corrupted = golden;
        corrupted.back() ^= std::byte{0x01};
        REQUIRE(decoder->reset());
        auto badChecksum = drain(*decoder, corrupted, corrupted.size(), 4096);
        REQUIRE(badChecksum.failed);
        CHECK(badChecksum.error.kind == ErrorKind::Integrity);
        CHECK(badChecksum.error.what == "zstd content checksum mismatch");

        REQUIRE(decoder->reset());
        auto truncated = drain(*decoder, std::span(golden).first(golden.size() - 1), 7, 4096);
        CHECK_FALSE(truncated.failed);
        CHECK_FALSE(truncated.finished);

        auto notZstd = golden;
        notZstd[0] = std::byte{0x29};
        REQUIRE(decoder->reset());
        auto badMagic = drain(*decoder, notZstd, notZstd.size(), 4096);
        REQUIRE(badMagic.failed);
        CHECK(badMagic.error.kind == ErrorKind::Malformed);
        CHECK(badMagic.error.what == "not a zstd frame");

        auto limited = ZstdDecoder::create({.maxWindowLog = 22});
        REQUIRE(limited);
        auto tooWide = drain(*limited, golden, golden.size(), 4096);
        REQUIRE(tooWide.failed);
        CHECK(tooWide.error.kind == ErrorKind::LimitExceeded);
    }

    SUBCASE("wide window, multi-frame and out-of-range limit") {
        std::string text(200'000, 'z');
        for (std::size_t index = 0; index < text.size(); index += 31) {
            text[index] = static_cast<char>('0' + index % 10);
        }
        auto frame = test::zstdCompress(asBytes(text), 24);
        REQUIRE_FALSE(frame.empty());

        auto narrow = ZstdDecoder::create({.maxWindowLog = 23});
        REQUIRE(narrow);
        auto rejected = drain(*narrow, frame, frame.size(), 4096);
        REQUIRE(rejected.failed);
        CHECK(rejected.error.kind == ErrorKind::LimitExceeded);
        CHECK(rejected.error.what == "zstd frame window exceeds limit");
        CHECK(rejected.output.empty());

        auto wide = ZstdDecoder::create({.maxWindowLog = 24});
        REQUIRE(wide);
        auto twoFrames = frame;
        twoFrames.insert(twoFrames.end(), frame.begin(), frame.end());
        auto first = drain(*wide, twoFrames, 1000, 7000);
        CHECK(first.finished);
        CHECK(first.output == text);
        CHECK(first.consumed == frame.size());
        auto second = drain(*wide, std::span(twoFrames).subspan(first.consumed), 1000, 7000);
        CHECK(second.finished);
        CHECK(second.output == text);

        auto outOfRange = ZstdDecoder::create({.maxWindowLog = 5});
        REQUIRE_FALSE(outOfRange);
        CHECK(outOfRange.error().kind == ErrorKind::Unsupported);
    }
}

TEST_CASE("DeflateEncoder output inflates back and short buffers or bad levels are refused") {
    std::string text;
    for (int line = 0; line < 2000; ++line) {
        text += "line " + std::to_string(line % 37) + " of a repetitive input\n";
    }

    for (int level : {0, 1, 6, 9}) {
        auto encoder = DeflateEncoder::create(level);
        REQUIRE(encoder);
        std::vector<std::byte> encoded(DeflateEncoder::compressBound(text.size()));
        auto size = encoder->compress(asBytes(text), encoded);
        REQUIRE(size);

        auto inflater = Inflater::create();
        REQUIRE(inflater);
        auto drained = drain(*inflater, std::span(encoded).first(*size), 4096, 4096);
        CHECK(drained.finished);
        CHECK(drained.output == text);
    }

    auto encoder = DeflateEncoder::create(6);
    REQUIRE(encoder);
    std::vector<std::byte> tiny(8);
    auto tooSmall = encoder->compress(asBytes(text), tiny);
    REQUIRE_FALSE(tooSmall);
    CHECK(tooSmall.error().kind == ErrorKind::LimitExceeded);

    CHECK_FALSE(DeflateEncoder::create(10));
    CHECK_FALSE(DeflateEncoder::create(-1));
}
