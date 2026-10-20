#include "formats/iso/eltorito.hpp"

#include <array>
#include <string>

namespace bale::iso {

namespace {

constexpr std::size_t catalogEntries = sectorSize / 32;
constexpr std::uint8_t headerValidation = 0x01;
constexpr std::uint8_t headerSection = 0x90;
constexpr std::uint8_t headerLastSection = 0x91;
constexpr std::uint8_t headerBootable = 0x88;
constexpr std::uint8_t headerNotBootable = 0x00;

constexpr std::uint64_t floppy1200Size = std::uint64_t{1200} * 1024;
constexpr std::uint64_t floppy1440Size = std::uint64_t{1440} * 1024;
constexpr std::uint64_t floppy2880Size = std::uint64_t{2880} * 1024;
constexpr std::uint64_t bootSectorBytes = 512;

[[nodiscard]] Result<std::uint64_t>
imageSize(std::uint8_t media, std::uint16_t sectors, const Limits& limits, std::uint64_t at) {
    switch (media) {
    case 0: {
        auto size = checkedMul<std::uint64_t>(sectors, bootSectorBytes);
        if (!size) {
            return fail(ErrorKind::Malformed, "El Torito image size overflows", at);
        }
        if (*size > limits.maxEntryBytes) {
            return fail(ErrorKind::LimitExceeded, "boot image exceeds size limit", at);
        }
        return *size;
    }
    case 1:
        return floppy1200Size;
    case 2:
        return floppy1440Size;
    case 3:
        return floppy2880Size;
    default:
        break;
    }
    return fail(ErrorKind::Unsupported, "El Torito hard-disk emulation is not supported", at);
}

[[nodiscard]] bool isPadding(std::span<const std::byte, 32> entry) {
    for (std::byte byte : entry) {
        if (byte != std::byte{0}) {
            return false;
        }
    }
    return true;
}

}

Result<std::vector<BootImage>> parseBootCatalog(
    const File& file,
    std::uint64_t fileSize,
    std::uint32_t catalogExtent,
    const Limits& limits
) {
    if (catalogExtent < systemSectors) {
        return fail(ErrorKind::Malformed, "El Torito catalog points into the system area");
    }
    auto catalogStart = sectorOffset(catalogExtent, Error::noOffset);
    if (!catalogStart) {
        return std::unexpected(catalogStart.error());
    }
    auto catalogEnd = checkedAdd(*catalogStart, sectorSize);
    if (!catalogEnd || *catalogEnd > fileSize) {
        return fail(ErrorKind::Truncated, "El Torito catalog extends past end of file");
    }

    std::array<std::byte, sectorSize> catalog{};
    auto read = file.readExactAt(*catalogStart, catalog);
    if (!read) {
        return std::unexpected(read.error());
    }

    std::uint32_t checksum = 0;
    for (std::size_t at = 0; at < 32; at += 2) {
        checksum += static_cast<std::uint32_t>(static_cast<unsigned char>(catalog[at])) |
            (static_cast<std::uint32_t>(static_cast<unsigned char>(catalog[at + 1])) << 8);
    }
    if (catalog[0] != std::byte{headerValidation} || catalog[30] != std::byte{0x55} ||
        catalog[31] != std::byte{0xAA} || (checksum & 0xFFFF) != 0) {
        return fail(ErrorKind::Malformed, "bad El Torito validation entry", *catalogStart);
    }

    std::vector<BootImage> images;
    for (std::size_t index = 1; index < catalogEntries; ++index) {
        std::span<const std::byte, 32> entry(catalog.data() + index * 32, 32);
        auto at = *catalogStart + index * 32;
        std::uint8_t header = static_cast<std::uint8_t>(entry[0]);
        if (header == headerSection || header == headerLastSection) {
            continue;
        }
        if (header != headerBootable && header != headerNotBootable) {
            return fail(ErrorKind::Malformed, "unknown El Torito catalog entry", at);
        }
        if (header == headerNotBootable && isPadding(entry)) {
            continue;
        }

        std::uint8_t media = static_cast<std::uint8_t>(entry[1]);
        std::uint16_t sectors = readLe16(entry.subspan(6, 2));
        auto size = imageSize(media, sectors, limits, at);
        if (!size) {
            return std::unexpected(size.error());
        }
        std::uint32_t extent = readLe32(entry.subspan(8, 4));
        if (extent < systemSectors) {
            return fail(ErrorKind::Malformed, "El Torito image points into the system area", at);
        }
        auto imageStart = sectorOffset(extent, at);
        if (!imageStart) {
            return std::unexpected(imageStart.error());
        }
        auto imageEnd = checkedAdd(*imageStart, *size);
        if (!imageEnd || *imageEnd > fileSize) {
            return fail(ErrorKind::Truncated, "El Torito image extends past end of file", at);
        }
        images.push_back(BootImage{.extent = extent, .size = *size});
    }
    return images;
}

}
