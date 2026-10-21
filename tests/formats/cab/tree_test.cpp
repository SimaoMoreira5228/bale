#include "formats/cab/tree.hpp"

#include <doctest/doctest.h>

#include <cstddef>
#include <vector>

using namespace bale;

namespace {

// NOTE: lengths below are hand-built (not taken from any cabinet) to pin the
// canonical-table contract from [MS-PATCH] 2.4: same-length symbols sort by
// symbol, levels start as far left as possible.

TEST_CASE("cab tree builds canonical codes for a small tree") {
    cab::Tree tree;
    tree.lengths = {2, 1, 3, 3};
    auto built = cab::buildTree(tree, 4);
    REQUIRE(built);
    CHECK(tree.counts[1] == 1);
    CHECK(tree.counts[2] == 1);
    CHECK(tree.counts[3] == 2);
    // Codes: symbol 1 -> "0", symbol 0 -> "10", symbols 2,3 -> "110","111".
    CHECK(tree.firstCode[1] == 0);
    CHECK(tree.firstCode[2] == 2);
    CHECK(tree.firstCode[3] == 6);
    REQUIRE(tree.symbols.size() == 4);
    CHECK(tree.symbols[0] == 1);
    CHECK(tree.symbols[1] == 0);
    CHECK(tree.symbols[2] == 2);
    CHECK(tree.symbols[3] == 3);
}

TEST_CASE("cab tree accepts empty and single-symbol trees") {
    cab::Tree empty;
    empty.lengths.assign(8, 0);
    CHECK(cab::buildTree(empty, 8));

    cab::Tree single;
    single.lengths.assign(8, 0);
    single.lengths[5] = 1;
    auto built = cab::buildTree(single, 8);
    REQUIRE(built);
    REQUIRE(single.symbols.size() == 1);
    CHECK(single.symbols[0] == 5);
}

TEST_CASE("cab tree rejects a length above 16 bits") {
    cab::Tree tree;
    tree.lengths.assign(4, 0);
    tree.lengths[1] = 17;
    auto built = cab::buildTree(tree, 4);
    REQUIRE_FALSE(built);
    CHECK(built.error().kind == ErrorKind::Malformed);
}

TEST_CASE("cab tree rejects an over-subscribed tree") {
    // NOTE: these are the real pretree lengths a mistuned LZX reader measured
    // in product.cab block 5 before the aligned-tree reset was fixed; the
    // Kraft sum is 49/32, so any conforming builder must refuse them.
    cab::Tree tree;
    tree.lengths = {7, 1, 4, 7, 1, 4, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    auto built = cab::buildTree(tree, tree.lengths.size());
    REQUIRE_FALSE(built);
    CHECK(built.error().kind == ErrorKind::Malformed);
}

TEST_CASE("cab tree accepts a exactly-full tree") {
    cab::Tree tree;
    tree.lengths = {1, 1};
    auto built = cab::buildTree(tree, 2);
    REQUIRE(built);
    CHECK(tree.symbols.size() == 2);
}

}
