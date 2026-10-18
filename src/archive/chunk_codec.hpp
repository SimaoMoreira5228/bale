#pragma once

#include "archive/writer_profile.hpp"
#include "base/error.hpp"
#include "codecs/decoders.hpp"
#include "codecs/encoders.hpp"
#include "codecs/lz4_frame.hpp"
#include "format/record.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace bale::archive {

struct EncodedChunk {
    CodecId codec = CodecId::Raw;
    std::span<const std::byte> bytes;
};

class ChunkEncoder {
  public:
    ChunkEncoder() = default;

    [[nodiscard]] static Result<ChunkEncoder>
    create(const CompressionProfile& profile, std::uint32_t chunkSize);

    [[nodiscard]] Result<EncodedChunk> encode(std::span<const std::byte> chunk);

  private:
    using Encoder = std::variant<std::monostate, ZstdEncoder, Lz4FrameEncoder>;

    Encoder encoder_;
    CodecId codec_ = CodecId::Raw;
    std::vector<std::byte> buffer_;
};

class ChunkDecoder {
  public:
    [[nodiscard]] Result<void>
    decode(CodecId codec, std::span<const std::byte> encoded, std::span<std::byte> output);

  private:
    [[nodiscard]] Result<void>
    decodeZstd(std::span<const std::byte> encoded, std::span<std::byte> output);

    std::optional<ZstdDecoder> zstd_;
    std::optional<Lz4FrameDecoder> lz4_;
};

}
