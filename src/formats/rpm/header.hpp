#pragma once

#include "base/error.hpp"
#include "formats/compressed/stream.hpp"
#include "formats/cpio/header.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::rpm {

// NOTE: all numeric header fields are big-endian; clean-room from the
// documented RPM lead/header layout, not from any implementation.

inline constexpr std::array<std::byte, 4> leadMagic{
    std::byte{0xED},
    std::byte{0xAB},
    std::byte{0xEE},
    std::byte{0xDB},
};

inline constexpr std::size_t leadSize = 96;
inline constexpr std::uint8_t majorV3 = 3;
inline constexpr std::uint8_t majorV4 = 4;

inline constexpr std::array<std::byte, 3> headerMagic{
    std::byte{0x8E},
    std::byte{0xAD},
    std::byte{0xE8},
};
inline constexpr std::uint8_t headerVersion = 1;
inline constexpr std::size_t headerPrefixSize = 16;
inline constexpr std::size_t headerIndexSize = 16;

inline constexpr std::uint32_t tagName = 1000;
inline constexpr std::uint32_t tagVersion = 1001;
inline constexpr std::uint32_t tagRelease = 1002;
inline constexpr std::uint32_t tagArch = 1022;
inline constexpr std::uint32_t tagOs = 1021;
inline constexpr std::uint32_t tagPayloadFormat = 1124;
inline constexpr std::uint32_t tagPayloadCompressor = 1125;
inline constexpr std::uint32_t tagPayloadFlags = 1126;

// NOTE: tag data types from the documented header layout.
enum class TagType : std::uint8_t {
    Null = 0,
    Char = 1,
    Int8 = 2,
    Int16 = 3,
    Int32 = 4,
    Int64 = 5,
    String = 6,
    Bin = 7,
    StringArray = 8,
    I18nString = 9,
};

struct Limits {
    std::uint64_t maxHeaderEntries = 100'000;
    std::uint64_t maxHeaderBytes = std::uint64_t{64} << 20;
    std::uint64_t maxStringBytes = std::uint64_t{1} << 20;
    std::uint64_t maxSignatureTags = 10'000;
    DecompressLimits decompress;
    cpio::Limits cpio;
};

struct Package {
    std::string name;
    std::string version;
    std::string release;
    std::string arch;
    std::string os;
    std::string payloadFormat;
    std::string payloadCompressor;
    std::string payloadFlags;
    std::uint64_t payloadOffset = 0;
    std::uint64_t payloadBytes = 0;
    std::vector<std::uint32_t> signatureTags;
    Compression compression = Compression::Gzip;
    bool uncompressed = false;
};

[[nodiscard]] bool looksLikeRpm(std::span<const std::byte> head);

[[nodiscard]] Result<Package>
parsePackage(const File& file, std::uint64_t fileSize, const Limits& limits);

}
