#include "formats/detect.hpp"

#include "format/envelope.hpp"
#include "formats/tar/header.hpp"
#include "formats/zip/reader.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <vector>

namespace bale {

std::string_view name(ArchiveFormat format) {
    switch (format) {
    case ArchiveFormat::Unknown:
        return "unknown";
    case ArchiveFormat::Bale:
        return "bale";
    case ArchiveFormat::Zip:
        return "zip";
    case ArchiveFormat::Tar:
        return "tar";
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
        return ArchiveFormat::Bale;
    }
    if (zip::looksLikeZip(headBytes, {})) {
        return ArchiveFormat::Zip;
    }
    if (headSize == tar::blockSize && tar::looksLikeTar(tar::Block(head))) {
        return ArchiveFormat::Tar;
    }

    auto tailSize = static_cast<std::size_t>(std::min<std::uint64_t>(*size, zip::maxEndSearch));
    std::vector<std::byte> tail(tailSize);
    auto tailRead = file.readExactAt(*size - tailSize, tail);
    if (!tailRead) {
        return std::unexpected(tailRead.error());
    }
    if (zip::looksLikeZip(headBytes, tail)) {
        return ArchiveFormat::Zip;
    }
    return ArchiveFormat::Unknown;
}

}
