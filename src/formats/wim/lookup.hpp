#pragma once

#include "base/error.hpp"
#include "formats/wim/header.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

namespace bale::wim {

inline constexpr std::size_t blobEntrySize = 50;
inline constexpr std::size_t hashSize = 20;

struct Blob {
    ResourceRef ref;
    std::uint16_t part = 0;
    std::uint32_t refcount = 0;
    std::array<std::byte, hashSize> hash{};
};

struct SolidBlob {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::array<std::byte, hashSize> hash{};
};

struct SolidRun {
    std::vector<ResourceRef> resources;
    std::vector<SolidBlob> blobs;
};

struct Lookup {
    std::vector<Blob> blobs;
    std::vector<ResourceRef> metadata;
    std::vector<SolidRun> solidRuns;
};

[[nodiscard]] Result<Lookup>
parseLookup(const File& file, const Header& header, std::uint64_t fileSize, const Limits& limits);

}
