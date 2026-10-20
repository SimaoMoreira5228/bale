#pragma once

#include "formats/iso/header.hpp"
#include "io/file.hpp"

#include <string>
#include <vector>

namespace bale::iso {

struct Node {
    std::string path;
    std::string target;
    std::vector<Extent> extents;
    std::uint64_t size = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mode = 0;
    EntryKind kind = EntryKind::Regular;
};

[[nodiscard]] Result<std::vector<Node>> walkTree(
    const File& file,
    std::uint64_t fileSize,
    std::uint32_t rootExtent,
    std::uint64_t rootSize,
    bool joliet,
    const Limits& limits,
    bool& sawRockRidge
);

}
