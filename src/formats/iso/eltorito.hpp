#pragma once

#include "formats/iso/header.hpp"
#include "io/file.hpp"

#include <cstdint>
#include <vector>

namespace bale::iso {

struct BootImage {
    std::uint32_t extent = 0;
    std::uint64_t size = 0;
};

[[nodiscard]] Result<std::vector<BootImage>> parseBootCatalog(
    const File& file,
    std::uint64_t fileSize,
    std::uint32_t catalogExtent,
    const Limits& limits
);

}
