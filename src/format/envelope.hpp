#pragma once

#include "base/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace bale {

inline constexpr std::size_t superblockSize = 64;
inline constexpr std::uint16_t formatMajor = 1;
inline constexpr std::uint16_t formatMinor = 0;
inline constexpr std::uint32_t knownRequiredFeatures = 0;

inline constexpr std::array superblockMagic{
    std::byte{0x42},
    std::byte{0x41},
    std::byte{0x4C},
    std::byte{0x45},
    std::byte{0x0D},
    std::byte{0x0A},
    std::byte{0x1A},
    std::byte{0x0A},
};

struct Superblock {
    std::uint16_t minor = formatMinor;
    std::uint32_t requiredFeatures = 0;
    std::uint32_t optionalFeatures = 0;
    std::array<std::byte, 16> archiveId{};
    std::int64_t creationTimeNs = 0;
};

[[nodiscard]] std::array<std::byte, superblockSize> encodeSuperblock(const Superblock& superblock);

[[nodiscard]] Result<Superblock> decodeSuperblock(std::span<const std::byte> data);

inline constexpr std::size_t footerSize = 96;
inline constexpr std::size_t commitDigestSize = 32;

inline constexpr std::array footerMagic{
    std::byte{0x42},
    std::byte{0x41},
    std::byte{0x4C},
    std::byte{0x45},
    std::byte{0x46},
    std::byte{0x54},
    std::byte{0x52},
    std::byte{0x31},
};

struct Footer {
    std::uint64_t commitOffset = 0;
    std::uint64_t commitLength = 0;
    std::uint64_t generation = 0;
    std::array<std::byte, commitDigestSize> commitDigest{};
};

[[nodiscard]] std::array<std::byte, footerSize> encodeFooter(const Footer& footer);

[[nodiscard]] Result<Footer>
decodeFooter(std::span<const std::byte> data, std::uint64_t footerOffset);

}
