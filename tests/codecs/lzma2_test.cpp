#include "codecs/decoders.hpp"
#include "codecs/lzma2.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace bale;

namespace {

using Bytes = std::vector<std::byte>;

Bytes mixedContent(std::size_t length) {
    Bytes out(length);
    std::uint32_t state = 0x51E7BED1;
    for (std::size_t index = 0; index < length; ++index) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bool noisy = (index / 2048) % 3 == 0;
        out[index] = noisy ? std::byte(state & 0xFF) : std::byte('a' + index % 23);
    }
    return out;
}

Bytes encode(Lzma2Encoder& encoder, std::span<const std::byte> input) {
    Bytes stream(Lzma2Encoder::compressBound(input.size()));
    auto size = encoder.compress(input, stream);
    REQUIRE(size);
    stream.resize(*size);
    return stream;
}

struct Drained {
    Bytes output;
    std::size_t consumed = 0;
    bool finished = false;
    Error error{};
    bool failed = false;
};

Drained drain(XzDecoder& decoder, std::span<const std::byte> input, std::size_t outputStep) {
    Drained drained;
    Bytes piece(outputStep);
    while (true) {
        auto step = decoder.decompress(input.subspan(drained.consumed), piece, true);
        if (!step) {
            drained.error = step.error();
            drained.failed = true;
            return drained;
        }

        drained.consumed += step->consumed;
        drained.output.insert(
            drained.output.end(),
            piece.begin(),
            piece.begin() + static_cast<std::ptrdiff_t>(step->produced)
        );
        if (step->finished) {
            drained.finished = true;
            return drained;
        }
        if (step->consumed == 0 && step->produced == 0) {
            return drained;
        }
    }
}

}

TEST_CASE("Lzma2Encoder round trips at every level and refuses levels outside 0-9") {
    constexpr std::array sizes{
        std::size_t{1},
        std::size_t{100},
        std::size_t{4096},
        std::size_t{65537},
        std::size_t{262144},
    };
    for (int level : {0, 6, 9}) {
        auto encoder = Lzma2Encoder::create(level);
        REQUIRE(encoder);
        auto decoder = XzDecoder::create();
        REQUIRE(decoder);
        for (std::size_t size : sizes) {
            CAPTURE(level);
            CAPTURE(size);
            Bytes input = mixedContent(size);
            Bytes stream = encode(*encoder, input);

            Bytes output(size);
            REQUIRE(decoder->reset());
            auto drained = drain(*decoder, stream, 8192);
            CHECK_FALSE(drained.failed);
            CHECK(drained.finished);
            CHECK(drained.output == input);
        }
    }

    CHECK_FALSE(Lzma2Encoder::create(-1));
    CHECK_FALSE(Lzma2Encoder::create(10));
}

TEST_CASE("Lzma2Encoder reports a short output buffer instead of truncating") {
    auto encoder = Lzma2Encoder::create(6);
    REQUIRE(encoder);
    Bytes input = mixedContent(65536);
    Bytes tiny(16);
    auto shortWrite = encoder->compress(input, tiny);
    REQUIRE_FALSE(shortWrite);
    CHECK(shortWrite.error().kind == ErrorKind::LimitExceeded);
}

TEST_CASE("XzDecoder rejects hostile lzma2 chunk streams and oversized output") {
    auto encoder = Lzma2Encoder::create(6);
    REQUIRE(encoder);
    auto decoder = XzDecoder::create();
    REQUIRE(decoder);
    Bytes input = mixedContent(32768);
    Bytes stream = encode(*encoder, input);

    Bytes garbage(stream.size(), std::byte{0x5A});
    REQUIRE(decoder->reset());
    auto badMagic = drain(*decoder, garbage, 4096);
    REQUIRE(badMagic.failed);
    CHECK(badMagic.error.kind == ErrorKind::Malformed);

    for (std::size_t length = 0; length < stream.size(); ++length) {
        CAPTURE(length);
        REQUIRE(decoder->reset());
        Bytes piece(4096);
        auto step = decoder->decompress(std::span(stream).first(length), piece, false);
        REQUIRE(step);
        CHECK_FALSE(step->finished);
    }

    Bytes trailing = stream;
    trailing.push_back(std::byte{0});
    REQUIRE(decoder->reset());
    auto extra = drain(*decoder, trailing, 4096);
    if (!extra.failed) {
        CHECK(extra.consumed != trailing.size());
    }

    Bytes shortOutput(input.size() - 1);
    REQUIRE(decoder->reset());
    auto step = decoder->decompress(stream, shortOutput, true);
    REQUIRE(step);
    CHECK_FALSE(step->finished);
}

TEST_CASE("XzDecoder enforces its memory limit on lzma2 chunk streams and is reusable") {
    auto encoder = Lzma2Encoder::create(6);
    REQUIRE(encoder);
    Bytes input = mixedContent(65536);
    Bytes stream = encode(*encoder, input);

    auto cramped = XzDecoder::create(XzLimits{.memLimitBytes = 4096});
    REQUIRE(cramped);
    auto rejected = drain(*cramped, stream, 4096);
    REQUIRE(rejected.failed);
    CHECK(rejected.error.kind == ErrorKind::LimitExceeded);

    auto decoder = XzDecoder::create();
    REQUIRE(decoder);
    auto first = drain(*decoder, stream, 4096);
    CHECK(first.finished);
    CHECK(first.output == input);
    CHECK(decoder->streamEnded());

    REQUIRE(decoder->reset());
    CHECK_FALSE(decoder->streamEnded());
    auto second = drain(*decoder, stream, 4096);
    CHECK(second.finished);
    CHECK(second.output == input);

    CHECK_FALSE(XzDecoder::create(XzLimits{.memLimitBytes = 0}));
}
