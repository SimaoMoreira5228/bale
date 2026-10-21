#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bale::cab {

// Canonical Huffman tables backing the LZX trees. Lengths follow the
// [MS-PATCH] 2.4 rule: same-length elements sort by symbol, and every
// level starts as far left as possible, so the path lengths alone
// rebuild the identical tree on both sides.
inline constexpr unsigned maxCodeBits = 16;

struct Tree {
    std::vector<std::uint8_t> lengths;
    std::vector<std::uint16_t> counts;
    std::vector<std::uint16_t> firstCode;
    std::vector<std::uint16_t> firstSymbol;
    std::vector<std::uint16_t> symbols;
};

// Rebuilds the canonical tables from `lengths` (exactly `symbols`
// entries). Rejects lengths above 16 bits and over-subscribed trees.
[[nodiscard]] Result<void> buildTree(Tree& tree, std::size_t symbols);

}
