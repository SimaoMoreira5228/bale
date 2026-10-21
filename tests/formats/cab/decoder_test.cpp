#include "formats/cab/lzx.hpp"

#include "cab_fixture.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace bale;

namespace {

using Bytes = std::vector<std::byte>;

std::uint64_t fnv1a(std::span<const std::byte> data) {
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (std::byte item : data) {
        hash ^= static_cast<std::uint64_t>(item);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

Bytes asBytes(auto const& array) {
    return Bytes(array.begin(), array.end());
}

// One-shot decode: single push, drained with a small buffer, then finish.
Result<Bytes> decodeOnce(
    unsigned windowBits,
    std::uint64_t totalOut,
    std::span<const std::byte> stream,
    std::size_t buffer = 64
) {
    auto decoder = cab::LzxDecoder::create(windowBits, totalOut);
    if (!decoder) {
        return std::unexpected(decoder.error());
    }
    if (auto pushed = decoder->push(stream); !pushed) {
        return std::unexpected(pushed.error());
    }
    Bytes out;
    std::vector<std::byte> chunk(buffer);
    while (out.size() < totalOut) {
        auto got = decoder->decode(chunk);
        if (!got) {
            return std::unexpected(got.error());
        }
        out.insert(
            out.end(),
            chunk.begin(),
            chunk.begin() + static_cast<std::ptrdiff_t>(got->produced)
        );
        if (got->produced == 0) {
            if (!got->starved) {
                break; // End of stream: the rest comes from finish().
            }
            return fail(ErrorKind::Truncated, "LZX stream ends early");
        }
    }
    auto tail = decoder->finish();
    if (!tail) {
        return std::unexpected(tail.error());
    }
    out.insert(out.end(), tail->begin(), tail->end());
    if (out.size() != totalOut) {
        return fail(ErrorKind::Truncated, "LZX stream ends early");
    }
    return out;
}

// Trickle decode: feed the stream `at a time, draining with a small buffer.
// Exercises every resume path (tree headers, raw-bit runs, tokens, frames).
Result<Bytes> decodeTrickle(
    unsigned windowBits,
    std::uint64_t totalOut,
    std::span<const std::byte> stream,
    std::size_t atATime,
    std::size_t buffer = 13
) {
    auto decoder = cab::LzxDecoder::create(windowBits, totalOut);
    if (!decoder) {
        return std::unexpected(decoder.error());
    }
    Bytes out;
    std::vector<std::byte> chunk(buffer);
    std::size_t fed = 0;
    std::size_t idle = 0;
    while (out.size() < totalOut && idle < 100000) {
        if (fed < stream.size()) {
            std::size_t take = atATime < stream.size() - fed ? atATime : stream.size() - fed;
            if (auto pushed = decoder->push(stream.subspan(fed, take)); !pushed) {
                return std::unexpected(pushed.error());
            }
            fed += take;
        }
        auto got = decoder->decode(chunk);
        if (!got) {
            return std::unexpected(got.error());
        }
        if (got->produced == 0) {
            if (!got->starved) {
                break; // End of stream: the rest comes from finish().
            }
            ++idle;
            if (fed >= stream.size()) {
                return fail(ErrorKind::Truncated, "LZX stream ends early");
            }
            continue;
        }
        idle = 0;
        out.insert(
            out.end(),
            chunk.begin(),
            chunk.begin() + static_cast<std::ptrdiff_t>(got->produced)
        );
    }
    auto tail = decoder->finish();
    if (!tail) {
        return std::unexpected(tail.error());
    }
    out.insert(out.end(), tail->begin(), tail->end());
    if (out.size() != totalOut) {
        return fail(ErrorKind::Truncated, "LZX stream ends early");
    }
    return out;
}

void checkFull(
    unsigned windowBits,
    std::span<const std::byte> stream,
    std::span<const std::byte> expected
) {
    auto once = decodeOnce(windowBits, expected.size(), stream);
    REQUIRE(once);
    CHECK(*once == Bytes(expected.begin(), expected.end()));
    for (std::size_t step = 1; step <= 9; ++step) {
        auto slow = decodeTrickle(windowBits, expected.size(), stream, step);
        REQUIRE(slow);
        CHECK(*slow == Bytes(expected.begin(), expected.end()));
    }
}

void checkHash(
    unsigned windowBits,
    std::span<const std::byte> stream,
    std::size_t totalOut,
    std::uint64_t expectedHash
) {
    auto once = decodeOnce(windowBits, totalOut, stream);
    REQUIRE(once);
    REQUIRE(once->size() == totalOut);
    CHECK(fnv1a(*once) == expectedHash);
    for (std::size_t step = 1; step <= 9; ++step) {
        auto slow = decodeTrickle(windowBits, totalOut, stream, step);
        REQUIRE(slow);
        REQUIRE(slow->size() == totalOut);
        CHECK(fnv1a(*slow) == expectedHash);
    }
}

TEST_CASE("cab LZX decodes literals plus an R0 match") {
    checkFull(15, cab::test::kLzxMicroMatchStream, cab::test::kLzxMicroMatchOut);
}

TEST_CASE("cab LZX decodes slots 8 and 9 with aligned offsets") {
    // NOTE: formatted offsets 16-31 use zero verbatim bits plus a 3-bit
    // aligned symbol ([MS-PATCH] 2.6.3); the pre-fix reader took 3 verbatim
    // bits instead and silently desynchronised on real cabinets.
    checkFull(15, cab::test::kLzxSlots89Stream, cab::test::kLzxSlots89Out);
}

TEST_CASE("cab LZX decodes an all-literal block") {
    checkFull(15, cab::test::kLzxLiteralsStream, cab::test::kLzxLiteralsOut);
}

TEST_CASE("cab LZX decodes a mid-block CFDATA split one byte at a time") {
    // NOTE: the 100-byte stream below is the verbatim lzx_split folder split
    // 18/82 across its two CFDATA records; step 18 reproduces the exact
    // historical resume failure (lost tree-code state across pushes).
    auto stream = asBytes(cab::test::kLzxSplitStream);
    auto once = decodeOnce(15, cab::test::kLzxSplitOutSize, stream);
    REQUIRE(once);
    CHECK(fnv1a(*once) == cab::test::kLzxSplitOutHash);
    for (std::size_t step :
         {std::size_t{1},
          std::size_t{2},
          std::size_t{3},
          std::size_t{5},
          std::size_t{7},
          std::size_t{13},
          std::size_t{17},
          std::size_t{18},
          std::size_t{19},
          std::size_t{64}}) {
        auto slow = decodeTrickle(15, cab::test::kLzxSplitOutSize, stream, step);
        REQUIRE(slow);
        CHECK(fnv1a(*slow) == cab::test::kLzxSplitOutHash);
    }
}

TEST_CASE("cab LZX decodes aligned blocks, E8 frames and raw blocks") {
    checkHash(
        15,
        cab::test::kLzxAlignedStream,
        cab::test::kLzxAlignedOutSize,
        cab::test::kLzxAlignedOutHash
    );
    checkHash(15, cab::test::kLzxE8Stream, cab::test::kLzxE8OutSize, cab::test::kLzxE8OutHash);
    checkHash(
        15,
        cab::test::kLzxOddRawStream,
        cab::test::kLzxOddRawOutSize,
        cab::test::kLzxOddRawOutHash
    );
}

TEST_CASE("cab LZX decodes a window-21 block with 32K frame alignment") {
    checkHash(
        21,
        cab::test::kLzxBig21Stream,
        cab::test::kLzxBig21OutSize,
        cab::test::kLzxBig21OutHash
    );
}

TEST_CASE("cab LZX rejects an unsupported window") {
    CHECK_FALSE(cab::LzxDecoder::create(14, 10));
    CHECK_FALSE(cab::LzxDecoder::create(22, 10));
    auto decoder = cab::LzxDecoder::create(15, 10);
    REQUIRE(decoder);
}

TEST_CASE("cab LZX rejects an invalid block type") {
    std::array<std::byte, 8> zeros{};
    auto failed = decodeOnce(15, 10, zeros);
    REQUIRE_FALSE(failed);
    CHECK(failed.error().kind == ErrorKind::Malformed);
}

TEST_CASE("cab LZX reports truncation when the folder ends mid-block") {
    auto stream = asBytes(cab::test::kLzxMicroMatchStream);
    auto half = decodeOnce(
        15,
        cab::test::kLzxMicroMatchOut.size(),
        std::span(stream).first(stream.size() / 2),
        64
    );
    REQUIRE_FALSE(half);
}

TEST_CASE("cab LZX rejects output past the folder size") {
    auto stream = asBytes(cab::test::kLzxMicroMatchStream);
    auto over = decodeOnce(15, 5, stream, 64);
    REQUIRE_FALSE(over);
    CHECK(over.error().kind == ErrorKind::Malformed);
}

}
