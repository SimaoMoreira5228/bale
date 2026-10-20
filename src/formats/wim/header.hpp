#pragma once

#include "base/error.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace bale::wim {

inline constexpr std::array<std::byte, 8> signature{
    std::byte{'M'},
    std::byte{'S'},
    std::byte{'W'},
    std::byte{'I'},
    std::byte{'M'},
    std::byte{0},
    std::byte{0},
    std::byte{0},
};

inline constexpr std::size_t headerDiskSize = 208;

inline constexpr std::uint32_t versionDefault = 0x00010D00;
inline constexpr std::uint32_t versionSolid = 0x00000E00;

inline constexpr std::uint32_t flagCompression = 0x00000002;
inline constexpr std::uint32_t flagSpanned = 0x00000008;
inline constexpr std::uint32_t flagWriteInProgress = 0x00000040;
inline constexpr std::uint32_t flagCompressXpress = 0x00020000;
inline constexpr std::uint32_t flagCompressLzx = 0x00040000;
inline constexpr std::uint32_t flagCompressLzms = 0x00080000;
inline constexpr std::uint32_t flagCompressXpress2 = 0x00200000;

inline constexpr std::uint8_t resFlagMetadata = 0x02;
inline constexpr std::uint8_t resFlagCompressed = 0x04;
inline constexpr std::uint8_t resFlagSpanned = 0x08;
inline constexpr std::uint8_t resFlagSolid = 0x10;

inline constexpr std::uint64_t solidResourceMagic = 0x0000000100000000ULL;

enum class Compression : std::uint8_t {
    None,
    Xpress,
    Lzx,
    Lzms,
};

struct Limits {
    std::uint64_t maxEntries = 1'000'000;
    std::uint64_t maxEntryBytes = std::uint64_t{1} << 38;
    std::uint64_t maxTotalBytes = std::uint64_t{1} << 40;
    std::size_t maxNameBytes = 4096;
    std::uint64_t maxXmlBytes = std::uint64_t{16} << 20;
    std::uint64_t maxLookupBytes = std::uint64_t{64} << 20;
    std::uint64_t maxChunkTableBytes = std::uint64_t{1} << 20;
    std::uint32_t maxImages = 100'000;
    std::uint32_t maxDepth = 64;
};

struct ResourceRef {
    std::uint64_t offset = 0;
    std::uint64_t sizeInWim = 0;
    std::uint64_t uncompressed = 0;
    std::uint8_t flags = 0;
};

struct Header {
    std::uint32_t version = 0;
    Compression compression = Compression::None;
    std::uint32_t chunkSize = 0;
    std::uint32_t imageCount = 0;
    std::uint32_t bootIndex = 0;
    ResourceRef lookup;
    ResourceRef xml;
    ResourceRef bootMeta;
};

[[nodiscard]] bool looksLikeWim(std::span<const std::byte> head);

[[nodiscard]] Result<Header> parseHeader(const File& file, std::uint64_t fileSize);

[[nodiscard]] std::string_view compressionName(Compression compression);

}
