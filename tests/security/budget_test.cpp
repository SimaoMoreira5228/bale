#include "security/budget.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <limits>

using namespace bale;

namespace {

constexpr auto max = std::numeric_limits<std::uint64_t>::max();

}

TEST_CASE("Budget rejects byte charges that would wrap near UINT64_MAX and keeps its state") {
    Budget budget(
        Limits{
            .maxTotalBytes = max,
            .maxEntryBytes = max,
        }
    );
    REQUIRE(budget.chargeEntry());
    REQUIRE(budget.chargeBytes(max - 1));

    auto wrapped = budget.chargeBytes(2);
    REQUIRE_FALSE(wrapped);
    CHECK(wrapped.error().kind == ErrorKind::LimitExceeded);
    CHECK(wrapped.error().what == "entry size limit exceeded");
    CHECK(budget.entryBytes() == max - 1);
    CHECK(budget.totalBytes() == max - 1);

    REQUIRE(budget.chargeBytes(1));
    CHECK(budget.totalBytes() == max);

    REQUIRE(budget.chargeEntry());
    CHECK(budget.entryBytes() == 0);
    REQUIRE(budget.chargeBytes(0));
    auto total = budget.chargeBytes(1);
    REQUIRE_FALSE(total);
    CHECK(total.error().what == "total decoded size limit exceeded");
    CHECK(budget.entryBytes() == 0);
    CHECK(budget.totalBytes() == max);

    CHECK(budget.checkDeclaredSize(1).error().what == "total decoded size limit exceeded");
}

TEST_CASE("Budget enforces entry count, per-entry and total limits at the exact boundary") {
    Budget budget(
        Limits{
            .maxEntries = 2,
            .maxTotalBytes = 150,
            .maxEntryBytes = 100,
        }
    );

    REQUIRE(budget.chargeEntry());
    REQUIRE(budget.checkDeclaredSize(100));
    CHECK(budget.checkDeclaredSize(101).error().what == "entry size limit exceeded");
    REQUIRE(budget.chargeBytes(60));
    REQUIRE(budget.chargeBytes(40));
    CHECK(budget.chargeBytes(1).error().what == "entry size limit exceeded");

    REQUIRE(budget.chargeEntry());
    CHECK(budget.checkDeclaredSize(51).error().what == "total decoded size limit exceeded");
    REQUIRE(budget.chargeBytes(50));
    CHECK(budget.chargeBytes(1).error().what == "total decoded size limit exceeded");
    CHECK(budget.totalBytes() == 150);

    auto third = budget.chargeEntry();
    REQUIRE_FALSE(third);
    CHECK(third.error().kind == ErrorKind::LimitExceeded);
    CHECK(third.error().what == "entry count limit exceeded");
    CHECK(budget.entries() == 2);
    CHECK(budget.entryBytes() == 50);
}

TEST_CASE("Budget flags compression ratios above the warning threshold without overflowing") {
    const Budget budget(Limits{});

    CHECK_FALSE(budget.compressionRatioExceeded(1, 1000));
    CHECK(budget.compressionRatioExceeded(1, 1001));
    CHECK(budget.compressionRatioExceeded(0, 1));
    CHECK_FALSE(budget.compressionRatioExceeded(0, 0));
    CHECK_FALSE(budget.compressionRatioExceeded(max / 999, max));
    CHECK(budget.compressionRatioExceeded(max / 1000 / 2, max));
}
