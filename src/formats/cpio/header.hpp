#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace bale::cpio {

inline constexpr std::string_view newcMagic = "070701";
inline constexpr std::string_view crcMagic = "070702";

inline constexpr std::string_view trailerName = "TRAILER!!!";

inline constexpr std::size_t headerSize = 110;
inline constexpr std::size_t fieldLength = 8;

inline constexpr std::size_t magicLength = 6;
inline constexpr std::size_t magicOffset = 0;
inline constexpr std::size_t inoOffset = 6;
inline constexpr std::size_t modeOffset = 14;
inline constexpr std::size_t uidOffset = 22;
inline constexpr std::size_t gidOffset = 30;
inline constexpr std::size_t nlinkOffset = 38;
inline constexpr std::size_t mtimeOffset = 46;
inline constexpr std::size_t filesizeOffset = 54;
inline constexpr std::size_t devMajorOffset = 62;
inline constexpr std::size_t devMinorOffset = 70;
inline constexpr std::size_t rdevMajorOffset = 78;
inline constexpr std::size_t rdevMinorOffset = 86;
inline constexpr std::size_t namesizeOffset = 94;
inline constexpr std::size_t checkOffset = 102;

struct Limits {
    std::uint64_t maxEntries = 1'000'000;
    std::uint64_t maxEntryBytes = std::uint64_t{1} << 38;
    std::uint64_t maxTotalBytes = std::uint64_t{1} << 40;
    std::size_t maxNameBytes = std::size_t{64} * 1024;
};

enum class EntryKind : std::uint8_t {
    Regular,
    Directory,
    Symlink,
    HardLink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
    Other,
};

struct Header {
    std::string_view name;
    std::uint64_t dataOffset = 0;
    std::uint64_t size = 0;
    std::uint64_t ino = 0;
    std::uint64_t nlink = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mode = 0;
    std::uint32_t fsMajor = 0;
    std::uint32_t fsMinor = 0;
    std::uint32_t devMajor = 0;
    std::uint32_t devMinor = 0;
    std::uint32_t check = 0;
    bool checksum = false;
    EntryKind kind = EntryKind::Regular;
    bool trailer = false;
};

[[nodiscard]] bool looksLikeCpio(std::span<const std::byte> head);

[[nodiscard]] Result<Header> parseHeader(
    std::span<const std::byte, headerSize> header,
    std::string_view name,
    std::uint64_t offset,
    std::uint64_t dataOffset
);

[[nodiscard]] std::uint64_t namePadding(std::uint64_t namesize);

[[nodiscard]] std::uint64_t dataPadding(std::uint64_t size);

}
