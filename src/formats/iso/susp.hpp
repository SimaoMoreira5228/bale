#pragma once

#include "formats/iso/header.hpp"
#include "io/file.hpp"

#include <cstdint>
#include <span>
#include <string>

namespace bale::iso {

struct SuspState {
    std::string names;
    bool namesDone = false;
    std::string link;
    bool linkAbsolute = false;
    std::uint32_t mode = 0;
    bool hasMode = false;
    std::int64_t stampSeconds = 0;
    bool hasStamp = false;
    bool sawRockRidge = false;
    bool relocated = false;
    std::uint64_t suspBytes = 0;
};

[[nodiscard]] Result<void> parseSystemUse(
    std::span<const std::byte> area,
    const File& file,
    std::uint64_t fileSize,
    const Limits& limits,
    SuspState& state,
    std::uint64_t recordOffset,
    std::uint32_t hops
);

}
