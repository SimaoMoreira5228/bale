#include "formats/iso/volume.hpp"

#include <array>
#include <string>

namespace bale::iso {

namespace {

constexpr std::size_t typeOffset = 0;
constexpr std::size_t magicOffset = 1;
constexpr std::size_t versionOffset = 6;
constexpr std::size_t bootSystemOffset = 7;
constexpr std::size_t bootSystemLength = 32;
constexpr std::size_t catalogOffset = 71;
constexpr std::size_t escapeOffset = 88;
constexpr std::size_t escapeLength = 32;
constexpr std::size_t blockSizeOffset = 128;
constexpr std::size_t pathTableSizeOffset = 132;
constexpr std::size_t pathTableLocOffset = 140;
constexpr std::size_t pathTableOptLocOffset = 144;
constexpr std::size_t pathTableLocBeOffset = 148;
constexpr std::size_t pathTableOptLocBeOffset = 152;
constexpr std::size_t rootRecordOffset = 156;
constexpr std::size_t rootRecordLength = 34;
constexpr std::uint64_t bridgeScanSectors = 16;

[[nodiscard]] bool isUdfMarker(std::string_view id) {
    for (std::string_view marker : udfMarkers) {
        if (id == marker) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool isUdfDescriptor(std::span<const std::byte> sector) {
    auto idAt = [&](std::size_t at) {
        if (at + 6 > sector.size()) {
            return false;
        }
        std::string_view id(reinterpret_cast<const char*>(sector.data() + at), 5);
        return isUdfMarker(id) && sector[at + 5] == std::byte{1};
    };
    return idAt(0) || idAt(1);
}

[[nodiscard]] Result<std::uint32_t> tableLocation(
    std::span<const std::byte> sector,
    std::size_t at,
    bool bigEndian,
    std::uint64_t offset
) {
    auto bytes = sector.subspan(at, 4);
    std::uint32_t location = bigEndian ? readBe32(bytes) : readLe32(bytes);
    if (location == 0) {
        return location;
    }
    auto start = sectorOffset(location, offset);
    if (!start) {
        return std::unexpected(start.error());
    }
    return location;
}

[[nodiscard]] Result<void> checkTableBounds(
    std::uint32_t location,
    std::uint64_t tableSize,
    std::uint64_t fileSize,
    std::uint64_t offset
) {
    if (location == 0 || tableSize == 0) {
        return {};
    }
    auto start = sectorOffset(location, offset);
    if (!start) {
        return std::unexpected(start.error());
    }
    auto end = checkedAdd(*start, tableSize);
    if (!end) {
        return fail(ErrorKind::Malformed, "ISO path table extends past the address space", offset);
    }
    if (*end > fileSize) {
        return fail(ErrorKind::Truncated, "ISO path table extends past end of file", offset);
    }
    return {};
}

struct RootReference {
    std::uint32_t extent = 0;
    std::uint64_t size = 0;
};

[[nodiscard]] Result<RootReference>
parseRootRecord(std::span<const std::byte> sector, std::uint64_t offset) {
    if (sector[rootRecordOffset] != std::byte{rootRecordLength}) {
        return fail(ErrorKind::Malformed, "ISO root record has an unexpected length", offset);
    }
    auto body = sector.subspan(rootRecordOffset, rootRecordLength);
    auto extent = bothLe32(body.subspan(2, 8));
    if (!extent) {
        return fail(ErrorKind::Malformed, "ISO root extent is not both-endian", offset);
    }
    auto size = bothLe32(body.subspan(10, 8));
    if (!size) {
        return fail(ErrorKind::Malformed, "ISO root size is not both-endian", offset);
    }
    if ((static_cast<std::uint8_t>(body[25]) & 0x02) == 0) {
        return fail(ErrorKind::Malformed, "ISO root record is not a directory", offset);
    }
    if (body[26] != std::byte{0} || body[27] != std::byte{0}) {
        return fail(ErrorKind::Unsupported, "ISO root directory uses interleaved extents", offset);
    }
    if (body[32] != std::byte{1} || body[33] != std::byte{0}) {
        return fail(ErrorKind::Malformed, "ISO root record has an unexpected name", offset);
    }
    if (*extent < systemSectors) {
        return fail(ErrorKind::Malformed, "ISO root directory points into the system area", offset);
    }
    return RootReference{.extent = *extent, .size = *size};
}

[[nodiscard]] Result<void> checkBlockSize(std::span<const std::byte> sector, std::uint64_t offset) {
    std::uint16_t little = readLe16(sector.subspan(blockSizeOffset, 2));
    auto bigBytes = sector.subspan(blockSizeOffset + 2, 2);
    std::uint16_t big = static_cast<std::uint16_t>(static_cast<std::uint8_t>(bigBytes[0]) << 8) |
        static_cast<std::uint16_t>(static_cast<std::uint8_t>(bigBytes[1]));
    if (little != big) {
        return fail(ErrorKind::Malformed, "ISO logical block size is not both-endian", offset);
    }
    if (little != sectorSize) {
        return fail(
            ErrorKind::Unsupported,
            "only 2048-byte ISO logical sectors are supported",
            offset
        );
    }
    return {};
}

[[nodiscard]] Result<void> checkPathTables(
    std::span<const std::byte> sector,
    std::uint64_t fileSize,
    const Limits& limits,
    std::uint64_t offset
) {
    auto tableSize = bothLe32(sector.subspan(pathTableSizeOffset, 8));
    if (!tableSize) {
        return fail(ErrorKind::Malformed, "ISO path table size is not both-endian", offset);
    }
    if (*tableSize > limits.maxPathTableBytes) {
        return fail(ErrorKind::LimitExceeded, "ISO path table exceeds limit", offset);
    }
    if (*tableSize == 0) {
        return {};
    }

    auto loc = tableLocation(sector, pathTableLocOffset, false, offset);
    if (!loc) {
        return std::unexpected(loc.error());
    }
    auto optLoc = tableLocation(sector, pathTableOptLocOffset, false, offset);
    if (!optLoc) {
        return std::unexpected(optLoc.error());
    }
    auto locBe = tableLocation(sector, pathTableLocBeOffset, true, offset);
    if (!locBe) {
        return std::unexpected(locBe.error());
    }
    auto optLocBe = tableLocation(sector, pathTableOptLocBeOffset, true, offset);
    if (!optLocBe) {
        return std::unexpected(optLocBe.error());
    }
    if (*loc == 0 && *optLoc == 0 && *locBe == 0 && *optLocBe == 0) {
        return fail(ErrorKind::Malformed, "ISO path table without a location", offset);
    }

    for (std::uint32_t location : {*loc, *optLoc, *locBe, *optLocBe}) {
        auto checked = checkTableBounds(location, *tableSize, fileSize, offset);
        if (!checked) {
            return checked;
        }
    }
    return {};
}

}

Result<Volume> parseVolumes(const File& file, std::uint64_t fileSize, const Limits& limits) {
    Volume volume;
    bool primary = false;
    bool done = false;
    std::uint32_t terminatorSector = 0;

    for (std::uint64_t index = 0; index < maxVolumeDescriptors && !done; ++index) {
        auto sectorNumber = static_cast<std::uint32_t>(firstVolumeSector + index);
        auto at = sectorOffset(sectorNumber, Error::noOffset);
        if (!at) {
            return std::unexpected(at.error());
        }
        auto end = checkedAdd(*at, sectorSize);
        if (!end || *end > fileSize) {
            return fail(ErrorKind::Truncated, "ISO image ends inside volume descriptors", *at);
        }

        std::array<std::byte, sectorSize> sector{};
        auto read = file.readExactAt(*at, sector);
        if (!read) {
            return std::unexpected(read.error());
        }

        std::string_view id(reinterpret_cast<const char*>(sector.data() + magicOffset), 5);
        if (id != volumeMagic) {
            if (isUdfMarker(id)) {
                return fail(
                    ErrorKind::Unsupported,
                    "UDF bridges are not supported, ISO 9660 data only",
                    *at
                );
            }
            return fail(ErrorKind::Malformed, "unknown ISO volume descriptor", *at);
        }

        std::uint8_t type = static_cast<std::uint8_t>(sector[typeOffset]);
        switch (type) {
        case descriptorTerminator: {
            if (sector[versionOffset] != std::byte{1}) {
                return fail(ErrorKind::Malformed, "unknown ISO volume descriptor", *at);
            }
            terminatorSector = sectorNumber;
            done = true;
            break;
        }
        case descriptorPrimary: {
            if (primary || index != 0 || sector[versionOffset] != std::byte{1}) {
                return fail(ErrorKind::Malformed, "misplaced ISO primary descriptor", *at);
            }
            auto block = checkBlockSize(sector, *at);
            if (!block) {
                return std::unexpected(block.error());
            }
            auto tables = checkPathTables(sector, fileSize, limits, *at);
            if (!tables) {
                return std::unexpected(tables.error());
            }
            auto root = parseRootRecord(sector, *at);
            if (!root) {
                return std::unexpected(root.error());
            }
            volume.rootExtent = root->extent;
            volume.rootSize = root->size;
            primary = true;
            break;
        }
        case descriptorSupplementary: {
            if (!isJolietEscape(std::span(sector).subspan(escapeOffset, escapeLength))) {
                break;
            }
            if (volume.hasJoliet) {
                return fail(ErrorKind::Malformed, "duplicate ISO Joliet descriptor", *at);
            }
            auto block = checkBlockSize(sector, *at);
            if (!block) {
                return std::unexpected(block.error());
            }
            auto root = parseRootRecord(sector, *at);
            if (!root) {
                return std::unexpected(root.error());
            }
            volume.hasJoliet = true;
            volume.jolietExtent = root->extent;
            volume.jolietSize = root->size;
            break;
        }
        case descriptorBoot: {
            std::string_view system(
                reinterpret_cast<const char*>(sector.data() + bootSystemOffset),
                bootSystemLength
            );
            if (!system.starts_with(elToritoId)) {
                break;
            }
            if (volume.bootCatalog) {
                return fail(ErrorKind::Unsupported, "multiple El Torito boot records", *at);
            }
            volume.bootCatalog = readLe32(std::span(sector).subspan(catalogOffset, 4));
            break;
        }
        default:
            return fail(ErrorKind::Malformed, "unknown ISO volume descriptor type", *at);
        }
    }

    if (!done) {
        return fail(ErrorKind::Malformed, "ISO image without a descriptor terminator");
    }
    if (!primary) {
        return fail(ErrorKind::Malformed, "ISO image without a primary descriptor");
    }

    // NOTE: a UDF bridge carries a valid ISO namespace past the
    // terminator, so probe the following sectors and refuse the image
    // instead of presenting the ISO view as the whole disc.
    for (std::uint64_t after = 1; after <= bridgeScanSectors; ++after) {
        auto probe = checkedAdd<std::uint64_t>(terminatorSector, after);
        if (!probe) {
            break;
        }
        auto at = sectorOffset(static_cast<std::uint32_t>(*probe), Error::noOffset);
        if (!at) {
            break;
        }
        auto end = checkedAdd(*at, sectorSize);
        if (!end || *end > fileSize) {
            break;
        }
        std::array<std::byte, sectorSize> sector{};
        auto read = file.readExactAt(*at, sector);
        if (!read) {
            return std::unexpected(read.error());
        }
        if (isUdfDescriptor(sector)) {
            return fail(
                ErrorKind::Unsupported,
                "UDF bridges are not supported, ISO 9660 data only",
                *at
            );
        }
    }

    auto checkRoot = [&](std::uint32_t extent, std::uint64_t size) -> Result<void> {
        if (extent < systemSectors) {
            return fail(ErrorKind::Malformed, "ISO directory extent points into the system area");
        }
        if (size == 0 || size > limits.maxDirectoryBytes) {
            return fail(
                size == 0 ? ErrorKind::Malformed : ErrorKind::LimitExceeded,
                size == 0 ? "ISO directory without data" : "ISO directory exceeds limit"
            );
        }
        auto start = sectorOffset(extent, Error::noOffset);
        if (!start) {
            return std::unexpected(start.error());
        }
        auto end = checkedAdd(*start, size);
        if (!end || *end > fileSize) {
            return fail(ErrorKind::Truncated, "ISO directory extends past end of file");
        }
        return Result<void>{};
    };

    auto root = checkRoot(volume.rootExtent, volume.rootSize);
    if (!root) {
        return std::unexpected(root.error());
    }
    if (volume.hasJoliet) {
        auto joliet = checkRoot(volume.jolietExtent, volume.jolietSize);
        if (!joliet) {
            return std::unexpected(joliet.error());
        }
    }
    return volume;
}

}
