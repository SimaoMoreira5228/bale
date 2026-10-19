#include "codecs/brotli.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <brotli/encode.h>

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

Bytes encode(BrotliEncoder& encoder, std::span<const std::byte> input) {
    Bytes stream(BrotliEncoder::compressBound(input.size()));
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

Drained drain(BrotliDecoder& decoder, std::span<const std::byte> input, std::size_t outputStep) {
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

Bytes largeWindowStream(std::span<const std::byte> input) {
    std::size_t bound = BrotliEncoderMaxCompressedSize(input.size());
    REQUIRE(bound != 0);
    Bytes stream(bound);
    std::size_t encodedSize = stream.size();
    auto ok = BrotliEncoderCompress(
        BROTLI_MAX_QUALITY,
        BROTLI_LARGE_MAX_WINDOW_BITS,
        BROTLI_MODE_GENERIC,
        input.size(),
        reinterpret_cast<const std::uint8_t*>(input.data()),
        &encodedSize,
        reinterpret_cast<std::uint8_t*>(stream.data())
    );
    REQUIRE(ok == BROTLI_TRUE);
    stream.resize(encodedSize);
    return stream;
}

}

TEST_CASE("BrotliEncoder accepts every quality 0-11 and round trips through the decoder") {
    for (int level = minBrotliLevel; level <= maxBrotliLevel; ++level) {
        CAPTURE(level);
        CHECK(BrotliEncoder::create(level));
    }
    CHECK_FALSE(BrotliEncoder::create(minBrotliLevel - 1));
    CHECK_FALSE(BrotliEncoder::create(maxBrotliLevel + 1));

    constexpr std::array sizes{
        std::size_t{0},
        std::size_t{1},
        std::size_t{100},
        std::size_t{4096},
        std::size_t{65537},
        std::size_t{262144},
    };
    for (int level : {0, 1, 6, 11}) {
        auto encoder = BrotliEncoder::create(level);
        REQUIRE(encoder);
        auto decoder = BrotliDecoder::create();
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
}

TEST_CASE("BrotliEncoder reports a short output buffer instead of truncating") {
    auto encoder = BrotliEncoder::create(11);
    REQUIRE(encoder);
    Bytes input = mixedContent(65536);
    Bytes tiny(16);
    auto shortWrite = encoder->compress(input, tiny);
    REQUIRE_FALSE(shortWrite);
    CHECK(shortWrite.error().kind == ErrorKind::LimitExceeded);
}

TEST_CASE("BrotliDecoder rejects hostile chunk streams and oversized output") {
    auto encoder = BrotliEncoder::create(6);
    REQUIRE(encoder);
    auto decoder = BrotliDecoder::create();
    REQUIRE(decoder);
    Bytes input = mixedContent(32768);
    Bytes stream = encode(*encoder, input);

    // NOTE: unlike xz, brotli has no magic: a 0x5A fill happens to parse as a valid empty
    // stream, so hostile inputs are fills the decoder actually refuses.
    for (std::byte fill : {std::byte{0x00}, std::byte{0xFF}}) {
        CAPTURE(fill);
        Bytes garbage(stream.size(), fill);
        REQUIRE(decoder->reset());
        auto badMagic = drain(*decoder, garbage, 4096);
        REQUIRE(badMagic.failed);
        CHECK(badMagic.error.kind == ErrorKind::Malformed);
    }

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

TEST_CASE("BrotliDecoder refuses streams outside the RFC 7932 window and is reusable") {
    auto decoder = BrotliDecoder::create();
    REQUIRE(decoder);
    Bytes input = mixedContent(65536);
    Bytes stream = largeWindowStream(input);

    REQUIRE(decoder->reset());
    auto rejected = drain(*decoder, stream, 4096);
    REQUIRE(rejected.failed);
    CHECK(rejected.error.kind == ErrorKind::Unsupported);

    auto encoder = BrotliEncoder::create(6);
    REQUIRE(encoder);
    Bytes plain = encode(*encoder, input);

    REQUIRE(decoder->reset());
    auto first = drain(*decoder, plain, 4096);
    CHECK(first.finished);
    CHECK(first.output == input);

    REQUIRE(decoder->reset());
    auto second = drain(*decoder, plain, 4096);
    CHECK(second.finished);
    CHECK(second.output == input);
}
