#include "archive/chunk_codec.hpp"

#include <array>
#include <utility>

namespace bale::archive {

Result<ChunkEncoder>
ChunkEncoder::create(const CompressionProfile& profile, std::uint32_t chunkSize) {
    ChunkEncoder chunkEncoder;
    chunkEncoder.codec_ = profile.codec;
    switch (profile.codec) {
    case CodecId::Raw:
        return chunkEncoder;
    case CodecId::Zstd: {
        auto encoder = ZstdEncoder::create(profile.level);
        if (!encoder) {
            return std::unexpected(encoder.error());
        }
        chunkEncoder.encoder_.emplace<ZstdEncoder>(std::move(*encoder));
        chunkEncoder.buffer_.resize(ZstdEncoder::compressBound(chunkSize));
        return chunkEncoder;
    }
    case CodecId::Lz4: {
        auto encoder = Lz4FrameEncoder::create(profile.level);
        if (!encoder) {
            return std::unexpected(encoder.error());
        }
        chunkEncoder.encoder_.emplace<Lz4FrameEncoder>(std::move(*encoder));
        chunkEncoder.buffer_.resize(Lz4FrameEncoder::compressBound(chunkSize));
        return chunkEncoder;
    }
    }
    return fail(ErrorKind::Unsupported, "writer codec not supported");
}

Result<EncodedChunk> ChunkEncoder::encode(std::span<const std::byte> chunk) {
    Result<std::size_t> compressed = chunk.size();
    if (auto* zstd = std::get_if<ZstdEncoder>(&encoder_)) {
        compressed = zstd->compress(chunk, buffer_);
    } else if (auto* lz4 = std::get_if<Lz4FrameEncoder>(&encoder_)) {
        compressed = lz4->compress(chunk, buffer_);
    }
    if (!compressed) {
        return std::unexpected(compressed.error());
    }

    if (*compressed >= chunk.size()) {
        return EncodedChunk{
            .codec = CodecId::Raw,
            .bytes = chunk,
        };
    }
    return EncodedChunk{
        .codec = codec_,
        .bytes = std::span<const std::byte>(buffer_).first(*compressed),
    };
}

Result<void> ChunkDecoder::decode(
    CodecId codec,
    std::span<const std::byte> encoded,
    std::span<std::byte> output
) {
    if (codec == CodecId::Zstd) {
        return decodeZstd(encoded, output);
    }
    if (codec != CodecId::Lz4) {
        return fail(ErrorKind::Unsupported, "chunk codec not supported");
    }

    if (!lz4_) {
        auto decoder = Lz4FrameDecoder::create();
        if (!decoder) {
            return std::unexpected(decoder.error());
        }
        lz4_.emplace(std::move(*decoder));
    }
    return lz4_->decompress(encoded, output);
}

Result<void>
ChunkDecoder::decodeZstd(std::span<const std::byte> encoded, std::span<std::byte> output) {
    if (!zstd_) {
        auto decoder = ZstdDecoder::create();
        if (!decoder) {
            return std::unexpected(decoder.error());
        }
        zstd_.emplace(std::move(*decoder));
    }
    auto reset = zstd_->reset();
    if (!reset) {
        return reset;
    }

    std::size_t consumed = 0;
    std::size_t produced = 0;
    bool finished = false;
    while (!finished) {
        std::array<std::byte, 1> probe{};
        bool full = produced == output.size();
        std::span<std::byte> target = full ? std::span<std::byte>(probe) : output.subspan(produced);
        auto step = zstd_->decompress(encoded.subspan(consumed), target);
        if (!step) {
            auto error = step.error();
            error.offset = consumed;
            return std::unexpected(error);
        }
        if (full && step->produced != 0) {
            return fail(ErrorKind::Malformed, "zstd chunk exceeds its declared size", consumed);
        }
        if (step->consumed == 0 && step->produced == 0 && !step->finished) {
            return fail(ErrorKind::Malformed, "zstd decoder made no progress", consumed);
        }

        consumed += step->consumed;
        if (!full) {
            produced += step->produced;
        }
        finished = step->finished;
    }

    if (consumed != encoded.size() || produced != output.size()) {
        return fail(ErrorKind::Malformed, "zstd chunk size or frame boundary is invalid", consumed);
    }
    return {};
}

}
