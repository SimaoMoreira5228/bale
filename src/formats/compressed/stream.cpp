#include "formats/compressed/stream.hpp"

#include <utility>

namespace bale {

Result<CompressedStream>
CompressedStream::open(File file, Compression compression, const DecompressLimits& limits) {
    switch (compression) {
    case Compression::Gzip: {
        gzip::Limits gzipLimits;
        gzipLimits.maxOutputBytes = limits.maxOutputBytes;
        gzipLimits.chunkBytes = limits.chunkBytes;

        auto stream = gzip::Stream::open(std::move(file), gzipLimits);
        if (!stream) {
            return std::unexpected(stream.error());
        }
        return CompressedStream(Codec(std::move(*stream)));
    }
    case Compression::Zstd: {
        zstd::Limits zstdLimits;
        zstdLimits.maxOutputBytes = limits.maxOutputBytes;
        zstdLimits.chunkBytes = limits.chunkBytes;

        auto stream = zstd::Stream::open(std::move(file), zstdLimits);
        if (!stream) {
            return std::unexpected(stream.error());
        }
        return CompressedStream(Codec(std::move(*stream)));
    }
    case Compression::None:
        break;
    }
    return fail(ErrorKind::Unsupported, "stream is not compressed");
}

Compression CompressedStream::compression() const {
    return std::holds_alternative<gzip::Stream>(codec_) ? Compression::Gzip : Compression::Zstd;
}

const gzip::Header* CompressedStream::gzipHeader() const {
    const auto* stream = std::get_if<gzip::Stream>(&codec_);
    return stream == nullptr ? nullptr : &stream->header();
}

std::uint64_t CompressedStream::outputBytes() const {
    return std::visit(
        [](const auto& stream) {
            return stream.outputBytes();
        },
        codec_
    );
}

Result<std::size_t> CompressedStream::read(std::span<std::byte> out) {
    return std::visit(
        [out](auto& stream) {
            return stream.read(out);
        },
        codec_
    );
}

}
