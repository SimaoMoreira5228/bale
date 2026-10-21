#pragma once

#include "base/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace bale::ar {

inline constexpr std::string_view magic = "!<arch>\n";

inline constexpr std::size_t headerSize = 60;

inline constexpr std::size_t nameLength = 16;
inline constexpr std::size_t dateLength = 12;
inline constexpr std::size_t uidLength = 6;
inline constexpr std::size_t gidLength = 6;
inline constexpr std::size_t modeLength = 8;
inline constexpr std::size_t sizeLength = 10;

inline constexpr std::size_t nameOffset = 0;
inline constexpr std::size_t dateOffset = 16;
inline constexpr std::size_t uidOffset = 28;
inline constexpr std::size_t gidOffset = 34;
inline constexpr std::size_t modeOffset = 40;
inline constexpr std::size_t sizeOffset = 48;
inline constexpr std::size_t terminatorOffset = 58;

inline constexpr std::array<std::byte, 2> terminator{
    std::byte{'`'},
    std::byte{'\n'},
};

struct Limits {
    std::uint64_t maxEntries = 1'000'000;
    std::uint64_t maxEntryBytes = std::uint64_t{1} << 38;
    std::uint64_t maxTotalBytes = std::uint64_t{1} << 40;
    std::uint64_t maxStringTableBytes = std::uint64_t{16} << 20;
    std::size_t maxNameBytes = 4096;
};

struct Member {
    std::string_view rawName;
    std::uint64_t headerOffset = 0;
    std::uint64_t dataOffset = 0;
    std::uint64_t size = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::uint32_t mode = 0;
};

[[nodiscard]] bool looksLikeAr(std::span<const std::byte> head);

[[nodiscard]] Result<Member>
parseMember(std::span<const std::byte, headerSize> header, std::uint64_t offset);

}
