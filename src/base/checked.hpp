#pragma once

#include <concepts>
#include <limits>
#include <optional>
#include <type_traits>
#include <utility>

namespace bale {

// NOTE: two type parameters, not one. std::size_t and std::uint64_t are the
// same type on LP64 Linux but different types on macOS, so a single T rejects
// calls that are perfectly sound. Both parameters must still be unsigned;
// signed arithmetic stays a compile error on purpose.
template <std::unsigned_integral A, std::unsigned_integral B>
[[nodiscard]] constexpr auto checkedAdd(A a, B b) {
    using Result = std::common_type_t<A, B>;
    auto wideA = static_cast<Result>(a);
    auto wideB = static_cast<Result>(b);
    if (wideB > std::numeric_limits<Result>::max() - wideA) {
        return std::optional<Result>{};
    }
    return std::optional<Result>{static_cast<Result>(wideA + wideB)};
}

template <std::unsigned_integral A, std::unsigned_integral B>
[[nodiscard]] constexpr auto checkedMul(A a, B b) {
    using Result = std::common_type_t<A, B>;
    auto wideA = static_cast<Result>(a);
    auto wideB = static_cast<Result>(b);
    if (wideA != 0 && wideB > std::numeric_limits<Result>::max() / wideA) {
        return std::optional<Result>{};
    }
    return std::optional<Result>{static_cast<Result>(wideA * wideB)};
}

template <std::integral To, std::integral From>
[[nodiscard]] constexpr std::optional<To> checkedCast(From value) {
    if (!std::in_range<To>(value)) {
        return std::nullopt;
    }
    return static_cast<To>(value);
}

template <std::unsigned_integral O, std::unsigned_integral L, std::unsigned_integral M>
[[nodiscard]] constexpr bool fitsWithin(O offset, L length, M limit) {
    using Result = std::common_type_t<O, L, M>;
    auto wideOffset = static_cast<Result>(offset);
    auto wideLength = static_cast<Result>(length);
    auto wideLimit = static_cast<Result>(limit);
    return wideOffset <= wideLimit && wideLength <= wideLimit - wideOffset;
}

}
