#pragma once

#include <bit>
#include <concepts>
#include <cstddef>
#include <cstring>

namespace bale {

template <std::unsigned_integral T> [[nodiscard]] inline T loadLe(const std::byte* source) {
    T value;
    std::memcpy(&value, source, sizeof(T));
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);
    }
    return value;
}

template <std::unsigned_integral T> inline void storeLe(std::byte* target, T value) {
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);
    }
    std::memcpy(target, &value, sizeof(T));
}

}
