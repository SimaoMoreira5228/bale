#pragma once

#include "formats/iso/header.hpp"

#include <cstdint>
#include <optional>

namespace bale::iso {

struct Volume {
    std::uint32_t rootExtent = 0;
    std::uint64_t rootSize = 0;
    bool hasJoliet = false;
    std::uint32_t jolietExtent = 0;
    std::uint64_t jolietSize = 0;
    std::optional<std::uint32_t> bootCatalog = std::nullopt;
};

[[nodiscard]] Result<Volume>
parseVolumes(const File& file, std::uint64_t fileSize, const Limits& limits);

}
