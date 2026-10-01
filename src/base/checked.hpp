#pragma once

#include <concepts>
#include <limits>
#include <optional>
#include <utility>

namespace bale {

template <std::unsigned_integral T> [[nodiscard]] constexpr std::optional<T> checkedAdd(T a, T b) {
    if (b > std::numeric_limits<T>::max() - a) {
        return std::nullopt;
    }
    return static_cast<T>(a + b);
}

template <std::unsigned_integral T> [[nodiscard]] constexpr std::optional<T> checkedMul(T a, T b) {
    if (a != 0 && b > std::numeric_limits<T>::max() / a) {
        return std::nullopt;
    }
    return static_cast<T>(a * b);
}

template <std::integral To, std::integral From>
[[nodiscard]] constexpr std::optional<To> checkedCast(From value) {
    if (!std::in_range<To>(value)) {
        return std::nullopt;
    }
    return static_cast<To>(value);
}

template <std::unsigned_integral T>
[[nodiscard]] constexpr bool fitsWithin(T offset, T length, T limit) {
    return offset <= limit && length <= limit - offset;
}

}
