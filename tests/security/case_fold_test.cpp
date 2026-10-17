#include "security/case_fold.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <string>

using namespace bale;

TEST_CASE("CaseFoldSet reports the first path that folds to the same name") {
    CaseFoldSet set;

    CHECK_FALSE(set.insertOrFindCollision("docs/Readme.TXT", 1));
    CHECK_FALSE(set.insertOrFindCollision("docs/Readme.TXT.bak", 2));
    CHECK_FALSE(set.insertOrFindCollision("docs/Readme.TX", 3));
    CHECK_FALSE(set.insertOrFindCollision("Docs", 4));
    CHECK(set.insertOrFindCollision("DOCS/readme.txt", 5) == 1);
    CHECK(set.insertOrFindCollision("docs/Readme.TXT", 6) == 1);
    CHECK(set.insertOrFindCollision("docs", 7) == 4);
    CHECK_FALSE(set.insertOrFindCollision("docs/caf\xC3\xA9", 8));
    CHECK(set.insertOrFindCollision("DOCS/CAF\xC3\xA9", 9) == 8);
    CHECK(set.size() == 5);

    set.clear();
    CHECK(set.size() == 0);
    CHECK_FALSE(set.insertOrFindCollision("DOCS/readme.txt", 10));
    CHECK(set.insertOrFindCollision("docs/README.TXT", 11) == 10);
}

TEST_CASE("CaseFoldSet keeps every entry across table growth") {
    CaseFoldSet set;
    constexpr std::uint64_t count = 50'000;

    for (std::uint64_t i = 0; i < count; ++i) {
        CHECK_FALSE(set.insertOrFindCollision("dir/file-" + std::to_string(i) + "-name", i));
    }
    REQUIRE(set.size() == count);

    std::uint64_t mismatches = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        auto existing =
            set.insertOrFindCollision("DIR/FILE-" + std::to_string(i) + "-NAME", count + i);
        if (existing != i) {
            ++mismatches;
        }
    }
    CHECK(mismatches == 0);
    CHECK(set.size() == count);
}
