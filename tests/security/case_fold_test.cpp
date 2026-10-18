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

TEST_CASE("CaseFoldSet applies Unicode simple case folding and nothing more") {
    CaseFoldSet set;

    CHECK_FALSE(set.insertOrFindCollision("\xCE\xA3", 1));
    CHECK(set.insertOrFindCollision("\xCF\x83", 2) == 1);
    CHECK(set.insertOrFindCollision("\xCF\x82", 3) == 1);

    CHECK_FALSE(set.insertOrFindCollision("unit-k", 4));
    CHECK(set.insertOrFindCollision("unit-\xE2\x84\xAA", 5) == 4);
    CHECK(set.insertOrFindCollision("UNIT-K", 6) == 4);

    CHECK_FALSE(set.insertOrFindCollision(
        "stra\xC3\x9F"
        "e",
        7
    ));
    CHECK_FALSE(set.insertOrFindCollision("strasse", 8));
    CHECK(
        set.insertOrFindCollision(
            "STRA\xE1\xBA\x9E"
            "E",
            9
        ) == 7
    );

    CHECK_FALSE(set.insertOrFindCollision("\xC4\xB0", 10));
    CHECK_FALSE(set.insertOrFindCollision("i", 11));
    CHECK_FALSE(set.insertOrFindCollision("\xC4\xB1", 12));
    CHECK(set.insertOrFindCollision("I", 13) == 11);
    CHECK(set.insertOrFindCollision("i\xCC\x87", 14) == 10);
    CHECK(set.insertOrFindCollision("I\xCC\x87", 15) == 10);

    CHECK_FALSE(set.insertOrFindCollision("\xEA\xAD\xB0", 16));
    CHECK(set.insertOrFindCollision("\xE1\x8E\xA0", 17) == 16);

    CHECK_FALSE(set.insertOrFindCollision("\xF0\x90\x90\x80.txt", 18));
    CHECK(set.insertOrFindCollision("\xF0\x90\x90\xA8.TXT", 19) == 18);
    CHECK(set.size() == 9);
}

TEST_CASE("CaseFoldSet treats canonically equivalent names as one name") {
    CaseFoldSet set;

    CHECK_FALSE(set.insertOrFindCollision("caf\xC3\xA9", 1));
    CHECK(set.insertOrFindCollision("cafe\xCC\x81", 2) == 1);
    CHECK(set.insertOrFindCollision("CAFE\xCC\x81", 3) == 1);
    CHECK(set.insertOrFindCollision("CAF\xC3\x89", 4) == 1);
    CHECK_FALSE(set.insertOrFindCollision("cafe", 5));

    CHECK_FALSE(set.insertOrFindCollision("\xE2\x84\xAB", 6));
    CHECK(set.insertOrFindCollision("\xC3\xA5", 7) == 6);
    CHECK(set.insertOrFindCollision("A\xCC\x8A", 8) == 6);

    CHECK_FALSE(set.insertOrFindCollision("\xE1\xBA\xAD", 9));
    CHECK(set.insertOrFindCollision("a\xCC\xA3\xCC\x82", 10) == 9);
    CHECK(set.insertOrFindCollision("A\xCC\x82\xCC\xA3", 11) == 9);

    CHECK_FALSE(set.insertOrFindCollision("\xCE\xB1\xCD\x85\xCC\xA3", 12));
    CHECK(set.insertOrFindCollision("\xCE\x91\xCC\xA3\xCD\x85", 13) == 12);

    CHECK_FALSE(set.insertOrFindCollision("\xEA\xB0\x80", 14));
    CHECK_FALSE(set.insertOrFindCollision("\xEA\xB0\x81", 15));
    CHECK(set.insertOrFindCollision("\xE1\x84\x80\xE1\x85\xA1", 16) == 14);
    CHECK(set.insertOrFindCollision("\xE1\x84\x80\xE1\x85\xA1\xE1\x86\xA8", 17) == 15);
}

TEST_CASE("CaseFoldSet reorders long hostile runs of combining marks") {
    const std::string acute = "\xCC\x81";
    const std::string dotBelow = "\xCC\xA3";
    std::string interleaved = "x";
    std::string acuteFirst = "X";
    std::string sorted = "x";
    for (int i = 0; i < 40; ++i) {
        interleaved += acute + dotBelow;
        acuteFirst += acute;
        sorted += dotBelow;
    }
    for (int i = 0; i < 40; ++i) {
        acuteFirst += dotBelow;
        sorted += acute;
    }

    CaseFoldSet set;
    CHECK_FALSE(set.insertOrFindCollision(interleaved, 1));
    CHECK(set.insertOrFindCollision(acuteFirst, 2) == 1);
    CHECK(set.insertOrFindCollision(sorted, 3) == 1);
    CHECK_FALSE(set.insertOrFindCollision(sorted + acute, 4));
}

TEST_CASE("CaseFoldSet keeps invalid UTF-8 bytes verbatim and folds around them") {
    CaseFoldSet set;

    CHECK_FALSE(set.insertOrFindCollision(
        "\xFF"
        "ABC\xC3\x89",
        1
    ));
    CHECK(
        set.insertOrFindCollision(
            "\xFF"
            "abc\xC3\xA9",
            2
        ) == 1
    );
    CHECK_FALSE(set.insertOrFindCollision("\xC3", 3));
    CHECK_FALSE(set.insertOrFindCollision("\xC3\xA9", 4));
    CHECK_FALSE(set.insertOrFindCollision(
        "\xC3"
        "X",
        5
    ));
    CHECK(set.insertOrFindCollision("\xC3x", 6) == 5);
    CHECK_FALSE(set.insertOrFindCollision("\xED\xA0\x80", 7));
    CHECK_FALSE(set.insertOrFindCollision("\xF0\x90\x90", 8));
    CHECK(set.insertOrFindCollision("\xED\xA0\x80", 9) == 7);
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
