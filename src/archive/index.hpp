#pragma once

#include "archive/chunk.hpp"
#include "base/error.hpp"
#include "format/record.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale::archive {

inline constexpr std::uint64_t indexSchemaVersion = 1;

struct IndexEntry {
    ChunkKey key;
    std::uint64_t recordOffset = 0;
    std::uint64_t recordLength = 0;
    CodecId codec = CodecId::Raw;
};

[[nodiscard]] Result<void>
encodeIndex(std::span<const IndexEntry> entries, std::vector<std::byte>& out);

[[nodiscard]] Result<void> decodeIndex(
    std::span<const std::byte> payload,
    std::uint64_t offset,
    std::uint64_t maxEntries,
    std::vector<IndexEntry>& out
);

[[nodiscard]] const IndexEntry* findChunk(std::span<const IndexEntry> entries, const ChunkKey& key);

}
