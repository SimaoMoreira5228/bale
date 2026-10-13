#include "base/endian.hpp"
#include "codecs/lz4_frame.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <lz4frame.h>

using namespace bale;

namespace {

using Bytes = std::vector<std::byte>;

constexpr std::size_t frameFlagsAt = 4;
constexpr std::size_t contentSizeAt = 6;
constexpr std::size_t headerChecksumAt = 14;
constexpr std::byte codec2Flags{0x68};

constexpr std::string_view goldenLz4Text = "bale lz4 golden vector, bale lz4 golden vector, "
                                           "bale lz4 golden vector, golden end\nstored block\n";

// NOTE: assembled by hand from the LZ4 frame specification: one compressed block with a 24-byte
// literal run and a 48-byte match, then one stored block. liblz4 1.9.4 (python-lz4) decodes it.
constexpr std::array<std::uint8_t, 81> goldenLz4{
    0x04, 0x22, 0x4d, 0x18, 0x68, 0x40, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe7, 0x29, 0x00, 0x00, 0x00, 0xff, 0x09, 0x62, 0x61, 0x6c, 0x65, 0x20, 0x6c, 0x7a,
    0x34, 0x20, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f,
    0x72, 0x2c, 0x20, 0x18, 0x00, 0x1d, 0xb0, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e, 0x20,
    0x65, 0x6e, 0x64, 0x0a, 0x0d, 0x00, 0x00, 0x80, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x64,
    0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x0a, 0x00, 0x00, 0x00, 0x00,
};

// NOTE: the header checksum of the same frame declaring one more byte of content.
constexpr std::byte goldenOversizedHeaderChecksum{0x43};

Bytes golden() {
    Bytes out;
    for (auto value : goldenLz4) {
        out.push_back(std::byte{value});
    }
    return out;
}

Bytes mixedContent(std::size_t length) {
    Bytes out(length);
    std::uint32_t state = 0x9E3779B9;
    for (std::size_t index = 0; index < length; ++index) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        bool noisy = (index / 4096) % 3 == 0;
        out[index] = noisy ? std::byte(state & 0xFF) : std::byte('a' + index % 23);
    }
    return out;
}

Bytes encode(Lz4FrameEncoder& encoder, std::span<const std::byte> input) {
    Bytes frame(Lz4FrameEncoder::compressBound(input.size()));
    auto size = encoder.compress(input, frame);
    REQUIRE(size);
    frame.resize(*size);
    return frame;
}

Bytes foreignFrame(std::span<const std::byte> input, const LZ4F_preferences_t& preferences) {
    Bytes frame(LZ4F_compressFrameBound(input.size(), &preferences));
    auto size =
        LZ4F_compressFrame(frame.data(), frame.size(), input.data(), input.size(), &preferences);
    REQUIRE_FALSE(LZ4F_isError(size));
    frame.resize(size);
    return frame;
}

}

TEST_CASE("Lz4FrameEncoder round trips around block boundaries with the codec 2 header") {
    constexpr std::size_t kilobyte = 1024;
    constexpr std::array sizes{
        std::size_t{1},
        64 * kilobyte - 1,
        64 * kilobyte,
        64 * kilobyte + 1,
        256 * kilobyte + 1,
        1024 * kilobyte,
        4096 * kilobyte + 1,
    };
    auto decoder = Lz4FrameDecoder::create();
    REQUIRE(decoder);
    for (int level : {0, 9}) {
        auto encoder = Lz4FrameEncoder::create(level);
        REQUIRE(encoder);
        for (std::size_t size : sizes) {
            CAPTURE(level);
            CAPTURE(size);
            Bytes input = mixedContent(size);
            Bytes frame = encode(*encoder, input);
            CHECK(frame[frameFlagsAt] == codec2Flags);
            CHECK(loadLe<std::uint64_t>(frame.data() + contentSizeAt) == size);

            Bytes output(size);
            REQUIRE(decoder->decompress(frame, output));
            CHECK(output == input);
        }
    }

    CHECK_FALSE(Lz4FrameEncoder::create(-1));
    CHECK_FALSE(Lz4FrameEncoder::create(13));
}

TEST_CASE("Lz4FrameDecoder decodes an independently assembled golden frame") {
    auto decoder = Lz4FrameDecoder::create();
    REQUIRE(decoder);
    Bytes frame = golden();
    Bytes output(goldenLz4Text.size());
    REQUIRE(decoder->decompress(frame, output));
    CHECK(
        std::string_view(reinterpret_cast<const char*>(output.data()), output.size()) ==
        goldenLz4Text
    );
}

TEST_CASE("Lz4FrameDecoder rejects frames outside codec 2 or the expected size") {
    auto decoder = Lz4FrameDecoder::create();
    REQUIRE(decoder);
    Bytes frame = golden();
    Bytes exact(goldenLz4Text.size());

    Bytes shorter(goldenLz4Text.size() - 1);
    Bytes longer(goldenLz4Text.size() + 1);
    CHECK_FALSE(decoder->decompress(frame, shorter));
    CHECK_FALSE(decoder->decompress(frame, longer));

    for (std::size_t length = 0; length < frame.size(); ++length) {
        CAPTURE(length);
        CHECK_FALSE(decoder->decompress(std::span(frame).first(length), exact));
    }

    Bytes trailing = frame;
    trailing.push_back(std::byte{0});
    CHECK_FALSE(decoder->decompress(trailing, exact));

    Bytes oversized = frame;
    storeLe(oversized.data() + contentSizeAt, std::uint64_t{goldenLz4Text.size() + 1});
    oversized[headerChecksumAt] = goldenOversizedHeaderChecksum;
    CHECK_FALSE(decoder->decompress(oversized, longer));
    CHECK_FALSE(decoder->decompress(oversized, exact));

    Bytes garbage(frame.size(), std::byte{0x5A});
    CHECK_FALSE(decoder->decompress(garbage, exact));

    Bytes input = mixedContent(std::size_t{200} * 1024);
    Bytes output(input.size());
    LZ4F_preferences_t preferences{};
    preferences.frameInfo.blockSizeID = LZ4F_max64KB;
    preferences.frameInfo.blockMode = LZ4F_blockIndependent;
    preferences.frameInfo.contentSize = input.size();
    REQUIRE(decoder->decompress(foreignFrame(input, preferences), output));
    CHECK(output == input);

    auto variant = preferences;
    variant.frameInfo.blockMode = LZ4F_blockLinked;
    CHECK_FALSE(decoder->decompress(foreignFrame(input, variant), output));
    variant = preferences;
    variant.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
    CHECK_FALSE(decoder->decompress(foreignFrame(input, variant), output));
    variant = preferences;
    variant.frameInfo.blockChecksumFlag = LZ4F_blockChecksumEnabled;
    CHECK_FALSE(decoder->decompress(foreignFrame(input, variant), output));
    variant = preferences;
    variant.frameInfo.contentSize = 0;
    CHECK_FALSE(decoder->decompress(foreignFrame(input, variant), output));

    REQUIRE(decoder->decompress(frame, exact));
}
