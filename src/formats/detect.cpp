#include "formats/detect.hpp"

#include "format/envelope.hpp"
#include "formats/ar/header.hpp"
#include "formats/bzip2/stream.hpp"
#include "formats/cab/header.hpp"
#include "formats/cpio/header.hpp"
#include "formats/gzip/header.hpp"
#include "formats/iso/header.hpp"
#include "formats/rpm/header.hpp"
#include "formats/sevenzip/reader.hpp"
#include "formats/tar/header.hpp"
#include "formats/wim/header.hpp"
#include "formats/xz/stream.hpp"
#include "formats/zip/reader.hpp"
#include "formats/zstd/stream.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <vector>

namespace bale {

namespace {

constexpr std::size_t sniffChunkBytes = std::size_t{4} << 10;

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
    case Container::SevenZip:
        return "7z";
    case Container::Tar:
        switch (format.compression) {
        case Compression::None:
            return "tar";
        case Compression::Gzip:
            return "tar.gz";
        case Compression::Zstd:
            return "tar.zst";
        case Compression::Xz:
            return "tar.xz";
        case Compression::Bzip2:
            return "tar.bz2";
        }
        return "tar";
    case Container::Ar:
        return "ar";
    case Container::Cpio:
        return "cpio";
    case Container::Cab:
        return "cab";
    case Container::Iso:
        return "iso";
    case Container::Wim:
        return "wim";
    case Container::Rpm:
        return "rpm";
    case Container::SingleFile:
        switch (format.compression) {
        case Compression::None:
            return "single";
        case Compression::Gzip:
            return "gzip";
        case Compression::Zstd:
            return "zstd";
        case Compression::Xz:
            return "xz";
        case Compression::Bzip2:
            return "bzip2";
        }
        return "single";
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
    if (sevenzip::looksLikeSevenZip(headBytes)) {
        return ArchiveFormat{.container = Container::SevenZip};
    }
    if (ar::looksLikeAr(headBytes)) {
        return ArchiveFormat{.container = Container::Ar};
    }
    if (cpio::looksLikeCpio(headBytes)) {
        return ArchiveFormat{.container = Container::Cpio};
    }
    if (cab::looksLikeCab(headBytes)) {
        return ArchiveFormat{.container = Container::Cab};
    }
    if (rpm::looksLikeRpm(headBytes)) {
        return ArchiveFormat{.container = Container::Rpm};
    }
    if (wim::looksLikeWim(headBytes)) {
        return ArchiveFormat{.container = Container::Wim};
    }
    if (*size >= iso::minImageSize) {
        std::array<std::byte, 7> probe{};
        auto probeRead = file.readExactAt(iso::systemSectors * iso::sectorSize, probe);
        if (!probeRead) {
            if (probeRead.error().kind == ErrorKind::Io) {
                return std::unexpected(probeRead.error());
            }
        } else if (iso::looksLikePrimaryDescriptor(probe)) {
            return ArchiveFormat{.container = Container::Iso};
        }
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
    if (xz::looksLikeXz(headBytes)) {
        return compressed(file, Compression::Xz);
    }
    if (bzip2::looksLikeBzip2(headBytes)) {
        return compressed(file, Compression::Bzip2);
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
