#pragma once

#include "base/error.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale::wim {

// NOTE: WIM LZX framing differs from CAB LZX framing: chunks carry no stream
// header, block sizes are a flag bit plus 16 (24 above 64 KiB windows) bits,
// E8 is unconditional with a fixed 12000000 filesize over the chunk, and
// there is no 32 KiB alignment padding. The Huffman/match core stays shared
// in formats/cab (tree.* plus LzxDecoder); this file only maps chunk sizes
// to windows, drives one chunk through the core, and undoes E8 per chunk.

inline constexpr std::uint32_t lzxE8FileSize = 12000000;
inline constexpr std::size_t lzxE8TailBytes = 10;

[[nodiscard]] Result<unsigned> windowBitsForChunk(std::uint64_t chunkSize, std::uint64_t at);

void undoE8Chunk(std::span<std::byte> chunk);

[[nodiscard]] Result<std::vector<std::byte>> decodeLzxChunk(
    const File& file,
    std::uint64_t storedAt,
    std::uint64_t storedSize,
    std::uint64_t uncompressedSize,
    std::uint64_t chunkSize,
    std::uint64_t at
);

}
