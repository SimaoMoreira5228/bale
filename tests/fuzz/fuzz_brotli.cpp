#include "archive/chunk_codec.hpp"
#include "base/endian.hpp"
#include "codecs/brotli.hpp"
#include "format/record.hpp"
#include "fuzz/memory_file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

constexpr std::size_t headerSize = 4;
constexpr std::size_t maxChunkOutput = std::size_t{1} << 20;
constexpr std::size_t maxStreamOutput = std::size_t{4} << 20;

void decodeChunk(std::span<const std::byte> encoded, std::size_t length) {
    static bale::archive::ChunkDecoder decoder;
    std::vector<std::byte> output(length);
    static_cast<void>(decoder.decode(bale::CodecId::Brotli, encoded, output));
}

void decodeStream(bale::BrotliDecoder& decoder, std::span<const std::byte> input) {
    if (!decoder.reset()) {
        return;
    }

    std::array<std::byte, 4096> buffer{};
    std::size_t produced = 0;
    while (produced <= maxStreamOutput) {
        auto step = decoder.decompress(input, buffer, true);
        if (!step) {
            return;
        }
        if (step->consumed > input.size() || step->produced > buffer.size()) {
            __builtin_trap();
        }
        input = input.subspan(step->consumed);
        produced += step->produced;
        if (step->finished || (step->consumed == 0 && step->produced == 0)) {
            return;
        }
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    if (input.size() < headerSize) {
        return 0;
    }

    auto selector = std::to_integer<std::uint8_t>(input[0]);
    std::size_t length = (bale::loadLe<std::uint32_t>(input.data()) >> 8) % (maxChunkOutput + 1);
    auto body = input.subspan(headerSize);

    if (selector % 2 == 0) {
        decodeChunk(body, length);
        return 0;
    }

    static auto decoder = bale::BrotliDecoder::create();
    if (decoder) {
        decodeStream(*decoder, body);
    }
    return 0;
}
