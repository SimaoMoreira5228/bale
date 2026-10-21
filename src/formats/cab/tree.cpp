#include "formats/cab/tree.hpp"

namespace bale::cab {

Result<void> buildTree(Tree& tree, std::size_t symbols) {
    tree.counts.assign(maxCodeBits + 1, 0);
    tree.firstCode.assign(maxCodeBits + 2, 0);
    tree.firstSymbol.assign(maxCodeBits + 2, 0);
    tree.symbols.clear();

    for (std::size_t symbol = 0; symbol < symbols; ++symbol) {
        if (tree.lengths[symbol] > maxCodeBits) {
            return fail(ErrorKind::Malformed, "LZX Huffman length is out of range");
        }
        if (tree.lengths[symbol] != 0) {
            ++tree.counts[tree.lengths[symbol]];
        }
    }

    std::uint32_t code = 0;
    std::uint16_t offset = 0;
    for (unsigned length = 1; length <= maxCodeBits; ++length) {
        code = (code + tree.counts[length - 1]) << 1;
        if (code + tree.counts[length] > (std::uint32_t{1} << length)) {
            return fail(ErrorKind::Malformed, "LZX Huffman tree is over-subscribed");
        }
        tree.firstCode[length] = static_cast<std::uint16_t>(code);
        tree.firstSymbol[length] = offset;
        offset += tree.counts[length];
    }

    tree.symbols.reserve(offset);
    for (unsigned length = 1; length <= maxCodeBits; ++length) {
        for (std::size_t symbol = 0; symbol < symbols; ++symbol) {
            if (tree.lengths[symbol] == length) {
                tree.symbols.push_back(static_cast<std::uint16_t>(symbol));
            }
        }
    }
    return {};
}

}
