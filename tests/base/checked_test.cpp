#include "base/checked.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <limits>

using namespace bale;

TEST_CASE("checked arithmetic rejects overflow at the boundary") {
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();

    SUBCASE("add and multiply") {
        CHECK(checkedAdd(max - 1, 1u) == max);
        CHECK_FALSE(checkedAdd(max, 1u));

        CHECK(checkedMul(max / 2, 2u) == max - 1);
        CHECK(checkedMul(0u, max) == 0);
        CHECK_FALSE(checkedMul(max / 2 + 1, 2u));
    }

    SUBCASE("checkedCast") {
        CHECK(checkedCast<std::uint8_t>(255) == 255);
        CHECK_FALSE(checkedCast<std::uint8_t>(256));
        CHECK_FALSE(checkedCast<std::uint32_t>(-1));
        CHECK_FALSE(checkedCast<std::int64_t>(std::numeric_limits<std::uint64_t>::max()));
    }

    SUBCASE("fitsWithin") {
        CHECK(fitsWithin(10u, 90u, 100u));
        CHECK_FALSE(fitsWithin(10u, 91u, 100u));
        CHECK_FALSE(fitsWithin(101u, 0u, 100u));
        CHECK_FALSE(fitsWithin(2u, max, 100u));
    }
}
