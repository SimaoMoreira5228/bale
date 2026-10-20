#pragma once

#include "base/error.hpp"
#include "formats/wim/header.hpp"
#include "formats/wim/lookup.hpp"
#include "formats/wim/resource.hpp"
#include "io/file.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace bale::wim {

inline constexpr std::uint32_t attrReadOnly = 0x00000001;
inline constexpr std::uint32_t attrDirectory = 0x00000010;
inline constexpr std::uint32_t attrReparse = 0x00000400;
inline constexpr std::uint32_t attrCompressed = 0x00000800;
inline constexpr std::uint32_t attrEncrypted = 0x00004000;

inline constexpr std::uint32_t reparseTagSymlink = 0xA000000C;
inline constexpr std::uint32_t reparseTagJunction = 0xA0000003;

enum class EntryKind : std::uint8_t {
    Regular,
    Directory,
    Symlink,
    HardLink,
    AlternateStream,
    Other,
};

struct Node {
    std::string path;
    std::string linkTarget;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mode = 0;
    EntryKind kind = EntryKind::Regular;
    std::array<std::byte, hashSize> hash{};
    bool hasData = false;
    std::uint32_t reparseTag = 0;
    std::array<std::byte, hashSize> reparseHash{};
    bool hasReparse = false;
};

[[nodiscard]] Result<std::vector<Node>> walkMetadata(const Resource& meta, const Limits& limits);

[[nodiscard]] Result<std::string>
parseReparseTarget(std::span<const std::byte> data, std::uint32_t tag);

}
