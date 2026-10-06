#include "formats/detect.hpp"

#include "format/envelope.hpp"
#include "formats/gzip/header.hpp"
#include "formats/tar/header.hpp"
#include "formats/zip/reader.hpp"
#include "formats/zstd/stream.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <vector>

namespace bale {

namespace {

constexpr std::size_t sniffChunkBytes = std::size_t{4} << 10;

// NOTE: decompresses at most one tar block; anything that fails to decode that far, short of an
// I/O error, is left for the real reader to report and counts as a single compressed file.
Result<Container> sniffCompressed(const File& file, Compression compression) {
    auto copy = file.duplicate();
    if (!copy) {
        return std::unexpected(copy.error());
    }

    DecompressLimits limits{
        .maxOutputBytes = tar::blockSize,
        .chunkBytes = sniffChunkBytes,
    };
    auto stream = CompressedStream::open(std::move(*copy), compression, limits);
    if (!stream) {
        if (stream.error().kind == ErrorKind::Io) {
            return std::unexpected(stream.error());
        }
        return Container::SingleFile;
    }

    std::array<std::byte, tar::blockSize> block{};
    std::size_t filled = 0;
    while (filled < block.size()) {
        auto count = stream->read(std::span(block).subspan(filled));
        if (!count) {
            if (count.error().kind == ErrorKind::Io) {
                return std::unexpected(count.error());
            }
            return Container::SingleFile;
        }
        if (*count == 0) {
            return Container::SingleFile;
        }
        filled += *count;
    }
    return tar::looksLikeTar(tar::Block(block)) ? Container::Tar : Container::SingleFile;
}

Result<ArchiveFormat> compressed(const File& file, Compression compression) {
    auto container = sniffCompressed(file, compression);
    if (!container) {
        return std::unexpected(container.error());
    }

    return ArchiveFormat{
        .container = *container,
        .compression = compression,
    };
}

}

std::string_view name(ArchiveFormat format) {
    switch (format.container) {
    case Container::Unknown:
        return "unknown";
    case Container::Bale:
        return "bale";
    case Container::Zip:
        return "zip";
    case Container::Tar:
        switch (format.compression) {
        case Compression::None:
            return "tar";
        case Compression::Gzip:
            return "tar.gz";
        case Compression::Zstd:
            return "tar.zst";
        }
        return "tar";
    case Container::SingleFile:
        return format.compression == Compression::Gzip ? "gzip" : "zstd";
    }
    return "unknown";
}

Result<ArchiveFormat> detectFormat(const File& file) {
    auto size = file.size();
    if (!size) {
        return std::unexpected(size.error());
    }

    std::array<std::byte, tar::blockSize> head{};
    auto headSize = static_cast<std::size_t>(std::min<std::uint64_t>(*size, head.size()));
    auto headRead = file.readExactAt(0, std::span(head).first(headSize));
    if (!headRead) {
        return std::unexpected(headRead.error());
    }
    auto headBytes = std::span<const std::byte>(head).first(headSize);

    if (std::ranges::starts_with(headBytes, superblockMagic)) {
        return ArchiveFormat{.container = Container::Bale};
    }
    if (zip::looksLikeZip(headBytes, {})) {
        return ArchiveFormat{.container = Container::Zip};
    }
    if (headSize == tar::blockSize && tar::looksLikeTar(tar::Block(head))) {
        return ArchiveFormat{.container = Container::Tar};
    }
    if (gzip::looksLikeGzip(headBytes)) {
        return compressed(file, Compression::Gzip);
    }
    if (zstd::looksLikeZstd(headBytes)) {
        return compressed(file, Compression::Zstd);
    }

    auto tailSize = static_cast<std::size_t>(std::min<std::uint64_t>(*size, zip::maxEndSearch));
    std::vector<std::byte> tail(tailSize);
    auto tailRead = file.readExactAt(*size - tailSize, tail);
    if (!tailRead) {
        return std::unexpected(tailRead.error());
    }
    if (zip::looksLikeZip(headBytes, tail)) {
        return ArchiveFormat{.container = Container::Zip};
    }
    return ArchiveFormat{};
}

}
