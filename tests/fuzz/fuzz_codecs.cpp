#include "archive/chunk_codec.hpp"
#include "base/endian.hpp"
#include "codecs/decoders.hpp"
#include "format/record.hpp"
#include "fuzz/memory_file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace {

constexpr std::size_t headerSize = 4;
constexpr std::size_t maxChunkOutput = std::size_t{1} << 20;
constexpr std::size_t maxStreamOutput = std::size_t{4} << 20;

void decodeChunk(bale::CodecId codec, std::span<const std::byte> encoded, std::size_t length) {
    static bale::archive::ChunkDecoder decoder;
    std::vector<std::byte> output(length);
    static_cast<void>(decoder.decode(codec, encoded, output));
}

struct XzRunDecoder {
    bale::XzDecoder decoder;

    [[nodiscard]] static std::optional<XzRunDecoder> create() {
        auto decoder = bale::XzDecoder::create();
        if (!decoder) {
            return std::nullopt;
        }
        return XzRunDecoder{std::move(*decoder)};
    }

    [[nodiscard]] bale::Result<bale::DecodeStep>
    decompress(std::span<const std::byte> input, std::span<std::byte> output) {
        return decoder.decompress(input, output, false);
    }

    [[nodiscard]] bale::Result<void> reset() {
        return decoder.reset();
    }
};

template <typename Decoder>
void decodeStream(Decoder& decoder, std::span<const std::byte> input, std::size_t window) {
    std::array<std::byte, 4096> buffer{};
    auto output = std::span(buffer).first(window);
    std::size_t produced = 0;
    while (produced <= maxStreamOutput) {
        auto step = decoder.decompress(input, output);
        if (!step) {
            return;
        }
        if (step->consumed > input.size() || step->produced > output.size()) {
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
    std::size_t window = 1 + length % 4096;

    switch (selector % 6) {
    case 0:
        decodeChunk(bale::CodecId::Zstd, body, length);
        break;
    case 1:
        decodeChunk(bale::CodecId::Lz4, body, length);
        break;
    case 2: {
        static auto inflater = bale::Inflater::create();
        if (inflater && inflater->reset()) {
            decodeStream(*inflater, body, window);
        }
        break;
    }
    case 3: {
        static auto zstd = bale::ZstdDecoder::create();
        if (zstd && zstd->reset()) {
            decodeStream(*zstd, body, window);
        }
        break;
    }
    case 4: {
        static auto bzip2 = bale::Bzip2Decoder::create();
        if (bzip2 && bzip2->reset()) {
            decodeStream(*bzip2, body, window);
        }
        break;
    }
    default: {
        static auto xz = XzRunDecoder::create();
        if (xz && xz->reset()) {
            decodeStream(*xz, body, window);
        }
        break;
    }
    }
    return 0;
}
