#pragma once

#include "base/checked.hpp"
#include "base/error.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace bale::iso {

inline constexpr std::uint64_t sectorSize = 2048;
inline constexpr std::uint64_t systemSectors = 16;
inline constexpr std::uint64_t firstVolumeSector = 16;
inline constexpr std::uint64_t maxVolumeDescriptors = 64;
inline constexpr std::uint64_t minImageSize = systemSectors * sectorSize + 7;

inline constexpr std::string_view volumeMagic = "CD001";

inline constexpr std::uint8_t descriptorBoot = 0;
inline constexpr std::uint8_t descriptorPrimary = 1;
inline constexpr std::uint8_t descriptorSupplementary = 2;
inline constexpr std::uint8_t descriptorTerminator = 255;

inline constexpr std::string_view elToritoId = "EL TORITO SPECIFICATION";

inline constexpr std::array<std::string_view, 5> udfMarkers = {
    "BEA01",
    "BOOT2",
    "NSR02",
    "NSR03",
    "TEA01",
};

struct Limits {
    std::uint64_t maxEntries = 1'000'000;
    std::uint64_t maxEntryBytes = std::uint64_t{1} << 38;
    std::uint64_t maxTotalBytes = std::uint64_t{1} << 40;
    std::size_t maxNameBytes = 4096;
    std::uint32_t maxPathBytes = 4096;
    std::uint64_t maxDirectoryBytes = std::uint64_t{64} << 20;
    std::uint64_t maxPathTableBytes = std::uint64_t{64} << 20;
    std::uint64_t maxSuspBytes = std::uint64_t{1} << 20;
    std::uint32_t maxDepth = 64;
    std::uint32_t maxContinuationHops = 32;
};

enum class EntryKind : std::uint8_t {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Other,
};

struct Extent {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
};

[[nodiscard]] bool looksLikePrimaryDescriptor(std::span<const std::byte> probe);

[[nodiscard]] Result<bool> isIsoImage(const File& file, std::uint64_t fileSize);

[[nodiscard]] std::uint16_t readLe16(std::span<const std::byte> bytes);

[[nodiscard]] std::uint32_t readLe32(std::span<const std::byte> bytes);

[[nodiscard]] std::uint32_t readBe32(std::span<const std::byte> bytes);

[[nodiscard]] std::optional<std::uint32_t> bothLe32(std::span<const std::byte> bytes);

[[nodiscard]] Result<std::uint64_t> sectorOffset(std::uint32_t sector, std::uint64_t at);

[[nodiscard]] std::optional<std::int64_t> shortTimeToUnix(std::span<const std::byte> date);

[[nodiscard]] std::optional<std::int64_t> longTimeToUnix(std::span<const std::byte> date);

[[nodiscard]] bool isJolietEscape(std::span<const std::byte> escapes);

[[nodiscard]] std::string_view stripVersionSuffix(std::string_view name);

}
