#include "base/checked.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <limits>

using namespace bale;

TEST_CASE("checked arithmetic rejects overflow at the boundary") {
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();

    CHECK(checkedAdd<std::uint64_t>(max - 1, 1) == max);
    CHECK_FALSE(checkedAdd<std::uint64_t>(max, 1));

    CHECK(checkedMul<std::uint64_t>(max / 2, 2) == max - 1);
    CHECK(checkedMul<std::uint64_t>(0, max) == 0);
    CHECK_FALSE(checkedMul<std::uint64_t>(max / 2 + 1, 2));
}

TEST_CASE("checkedCast rejects values outside the target range") {
    CHECK(checkedCast<std::uint8_t>(255) == 255);
    CHECK_FALSE(checkedCast<std::uint8_t>(256));
    CHECK_FALSE(checkedCast<std::uint32_t>(-1));
    CHECK_FALSE(checkedCast<std::int64_t>(std::numeric_limits<std::uint64_t>::max()));
}

TEST_CASE("fitsWithin handles ranges that would wrap") {
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();

    CHECK(fitsWithin<std::uint64_t>(10, 90, 100));
    CHECK_FALSE(fitsWithin<std::uint64_t>(10, 91, 100));
    CHECK_FALSE(fitsWithin<std::uint64_t>(101, 0, 100));
    CHECK_FALSE(fitsWithin<std::uint64_t>(2, max, 100));
}
