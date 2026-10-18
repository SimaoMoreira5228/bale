#pragma once

#include <cstdint>
#include <span>

namespace bale {

struct CodePointProperties {
    std::span<const char32_t> decomposition;
    std::int32_t foldDelta = 0;
    std::uint8_t combiningClass = 0;
};

[[nodiscard]] CodePointProperties codePointProperties(char32_t codePoint);

}
