#include "formats/compressed/stream.hpp"

#include <type_traits>
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
    case Compression::Xz: {
        xz::Limits xzLimits;
        xzLimits.maxOutputBytes = limits.maxOutputBytes;
        xzLimits.chunkBytes = limits.chunkBytes;

        auto stream = xz::Stream::open(std::move(file), xzLimits);
        if (!stream) {
            return std::unexpected(stream.error());
        }
        return CompressedStream(Codec(std::move(*stream)));
    }
    case Compression::Bzip2: {
        bzip2::Limits bzip2Limits;
        bzip2Limits.maxOutputBytes = limits.maxOutputBytes;
        bzip2Limits.chunkBytes = limits.chunkBytes;

        auto stream = bzip2::Stream::open(std::move(file), bzip2Limits);
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
    return std::visit(
        [](const auto& stream) -> Compression {
            using Stream = std::decay_t<decltype(stream)>;
            if constexpr (std::is_same_v<Stream, gzip::Stream>) {
                return Compression::Gzip;
            } else if constexpr (std::is_same_v<Stream, zstd::Stream>) {
                return Compression::Zstd;
            } else if constexpr (std::is_same_v<Stream, xz::Stream>) {
                return Compression::Xz;
            } else {
                return Compression::Bzip2;
            }
        },
        codec_
    );
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
