#include "parity/reed_solomon.hpp"

#include <doctest/doctest.h>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace bale;
using namespace bale::parity;

namespace {

// NOTE: golden field and codeword bytes below come from an independent Python
// NOTE: reference (GF(2^8), polynomial 0x11D, Cauchy x_j = 255-j, y_i = i),
// NOTE: not from this implementation, so agreement proves interop, not self-echo.
class XorShift {
  public:
    std::uint64_t operator()() {
        state_ ^= state_ << 13;
        state_ ^= state_ >> 7;
        state_ ^= state_ << 17;
        return state_;
    }

  private:
    std::uint64_t state_ = 0x9E3779B97F4A7C15;
};

std::vector<std::vector<std::byte>>
randomStore(std::uint32_t shards, std::size_t length, XorShift& random) {
    std::vector<std::vector<std::byte>> store(shards, std::vector<std::byte>(length));
    for (auto& shard : store) {
        for (std::byte& cell : shard) {
            cell = static_cast<std::byte>(random());
        }
    }
    return store;
}

void encodeStore(
    const ReedSolomon& coder,
    std::uint32_t dataShards,
    std::uint32_t parityShards,
    std::vector<std::vector<std::byte>>& store
) {
    std::vector<std::span<const std::byte>> data(dataShards);
    std::vector<std::span<std::byte>> parity(parityShards);
    for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
        data[shard] = store[shard];
    }
    for (std::uint32_t shard = 0; shard < parityShards; ++shard) {
        parity[shard] = store[dataShards + shard];
    }
    REQUIRE(coder.encode(data, parity));
}

bool verifyStore(
    const ReedSolomon& coder,
    std::uint32_t dataShards,
    std::uint32_t parityShards,
    const std::vector<std::vector<std::byte>>& store
) {
    std::vector<std::span<const std::byte>> data(dataShards);
    std::vector<std::span<const std::byte>> parity(parityShards);
    for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
        data[shard] = store[shard];
    }
    for (std::uint32_t shard = 0; shard < parityShards; ++shard) {
        parity[shard] = store[dataShards + shard];
    }
    auto verified = coder.verify(data, parity);
    REQUIRE(verified);
    return *verified;
}

bool repairMissing(
    const ReedSolomon& coder,
    std::uint32_t total,
    std::span<const std::uint32_t> missing,
    std::vector<std::vector<std::byte>>& work,
    std::vector<std::byte>& scratch
) {
    for (std::uint32_t shard : missing) {
        for (std::byte& cell : work[shard]) {
            cell = std::byte{0};
        }
    }
    std::vector<std::span<std::byte>> shards(total);
    for (std::uint32_t shard = 0; shard < total; ++shard) {
        shards[shard] = work[shard];
    }
    auto repaired = coder.repair(shards, missing, scratch);
    if (!repaired) {
        return false;
    }
    return true;
}

}

TEST_CASE("field arithmetic matches the published GF(2^8)/0x11D values") {
    CHECK(gf::exp(0) == 1);
    CHECK(gf::exp(1) == 2);
    CHECK(gf::exp(7) == 128);
    CHECK(gf::exp(8) == 29);
    CHECK(gf::exp(9) == 58);
    CHECK(gf::exp(255) == 1);
    CHECK(gf::exp(-1) == gf::exp(254));
    CHECK(gf::log(1).value_or(0xFF) == 0);
    CHECK(gf::log(2).value_or(0xFF) == 1);
    CHECK(gf::log(29).value_or(0xFF) == 8);
    CHECK(gf::multiply(0x53, 0xCA) == 0x8F);
    CHECK(gf::multiply(0, 5) == 0);
    CHECK(gf::multiply(7, 0) == 0);
    CHECK(gf::multiply(1, 0xAB) == 0xAB);
    CHECK(gf::inverse(1).value_or(0) == 1);
    CHECK(gf::inverse(0x53).value_or(0) == 0x8C);
    CHECK_FALSE(gf::inverse(0).has_value());
    CHECK_FALSE(gf::log(0).has_value());
    CHECK(gf::inverse(0x53).value_or(0) != 0);
    CHECK(gf::multiply(0x53, gf::inverse(0x53).value_or(0)) == 1);
}

TEST_CASE("encode matches the independent Cauchy reference vectors") {
    auto coder = ReedSolomon::make(2, 1);
    REQUIRE(coder);
    std::vector<std::vector<std::byte>> store = {
        {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}},
        {std::byte{0x10}, std::byte{0x20}, std::byte{0x30}, std::byte{0x40}},
        {std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00}},
    };
    encodeStore(*coder, 2, 1, store);
    CHECK(
        store[2] ==
        std::vector<std::byte>{std::byte{0x4E}, std::byte{0x9C}, std::byte{0xD2}, std::byte{0x25}}
    );

    auto coder42 = ReedSolomon::make(4, 2);
    REQUIRE(coder42);
    std::vector<std::vector<std::byte>> ascending(6, std::vector<std::byte>(8));
    for (std::uint32_t shard = 0; shard < 4; ++shard) {
        for (std::size_t index = 0; index < 8; ++index) {
            ascending[shard][index] =
                static_cast<std::byte>(static_cast<std::size_t>(shard) * 16 + index);
        }
    }
    encodeStore(*coder42, 4, 2, ascending);
    const std::vector<std::byte> expect0 = {
        std::byte{0xDD},
        std::byte{0xDE},
        std::byte{0xDB},
        std::byte{0xD8},
        std::byte{0xD1},
        std::byte{0xD2},
        std::byte{0xD7},
        std::byte{0xD4},
    };
    const std::vector<std::byte> expect1 = {
        std::byte{0xED},
        std::byte{0xEE},
        std::byte{0xEB},
        std::byte{0xE8},
        std::byte{0xE1},
        std::byte{0xE2},
        std::byte{0xE7},
        std::byte{0xE4},
    };
    CHECK(ascending[4] == expect0);
    CHECK(ascending[5] == expect1);

    auto coder11 = ReedSolomon::make(1, 1);
    REQUIRE(coder11);
    std::vector<std::vector<std::byte>> single = {
        {std::byte{0xAB}},
        {std::byte{0x00}},
    };
    encodeStore(*coder11, 1, 1, single);
    CHECK(single[1] == std::vector<std::byte>{std::byte{0x08}});
}

TEST_CASE("encode matches a wider 10+4 reference vector") {
    auto coder = ReedSolomon::make(10, 4);
    REQUIRE(coder);
    std::vector<std::vector<std::byte>> store(14, std::vector<std::byte>(16));
    for (std::uint32_t shard = 0; shard < 10; ++shard) {
        for (std::size_t index = 0; index < 16; ++index) {
            store[shard][index] =
                static_cast<std::byte>((static_cast<std::size_t>(shard) * 37 + index * 11) & 0xFF);
        }
    }
    encodeStore(*coder, 10, 4, store);
    const std::vector<std::vector<std::uint8_t>> expect = {
        {0x65,
         0x18,
         0xF2,
         0xEC,
         0x5F,
         0xB5,
         0x95,
         0x48,
         0x16,
         0xC3,
         0x25,
         0x5A,
         0x2B,
         0xE9,
         0xD2,
         0x91},
        {0xC3,
         0x07,
         0x0C,
         0x23,
         0xBC,
         0xB2,
         0x94,
         0xD5,
         0x03,
         0x39,
         0x7E,
         0x08,
         0xEA,
         0xBC,
         0x8D,
         0xD3},
        {0x9E,
         0xEE,
         0xF5,
         0x80,
         0x83,
         0x85,
         0x8C,
         0xBD,
         0x19,
         0x4D,
         0x75,
         0xF7,
         0x6A,
         0xF9,
         0x3F,
         0x17},
        {0x4B,
         0xA7,
         0x34,
         0x0C,
         0xCA,
         0x8E,
         0x76,
         0xB5,
         0x56,
         0xB0,
         0x74,
         0xEC,
         0x74,
         0xC7,
         0xE7,
         0xD9},
    };
    for (std::uint32_t row = 0; row < 4; ++row) {
        CAPTURE(row);
        REQUIRE(store[10 + row].size() == expect[row].size());
        for (std::size_t index = 0; index < 16; ++index) {
            CHECK(std::to_integer<std::uint8_t>(store[10 + row][index]) == expect[row][index]);
        }
    }
}

TEST_CASE("every erasure pattern within budget recovers small coders") {
    XorShift random;
    for (auto [dataShards, parityShards] :
         {std::pair<std::uint32_t, std::uint32_t>{1, 1}, {2, 1}, {4, 2}, {8, 1}}) {
        CAPTURE(dataShards);
        CAPTURE(parityShards);
        auto coder = ReedSolomon::make(dataShards, parityShards);
        REQUIRE(coder);
        const std::uint32_t total = dataShards + parityShards;
        const std::size_t length = 32;
        auto pristine = randomStore(total, length, random);
        encodeStore(*coder, dataShards, parityShards, pristine);
        REQUIRE(verifyStore(*coder, dataShards, parityShards, pristine));
        auto scratch = std::vector<std::byte>(*ReedSolomon::scratchBytes(dataShards, parityShards));

        for (std::uint32_t mask = 0; mask < (1U << total); ++mask) {
            if (static_cast<std::uint32_t>(std::popcount(mask)) > parityShards) {
                continue;
            }
            CAPTURE(mask);
            std::vector<std::uint32_t> missing;
            for (std::uint32_t shard = 0; shard < total; ++shard) {
                if ((mask & (1U << shard)) != 0) {
                    missing.push_back(shard);
                }
            }
            auto work = pristine;
            CHECK(repairMissing(*coder, total, missing, work, scratch));
            CHECK(verifyStore(*coder, dataShards, parityShards, work));
            CHECK(work == pristine);
        }
    }
}

TEST_CASE("sampled erasure patterns recover wider coders") {
    XorShift random;
    for (auto [dataShards, parityShards] :
         {std::pair<std::uint32_t, std::uint32_t>{10, 4}, {17, 3}, {32, 4}}) {
        CAPTURE(dataShards);
        CAPTURE(parityShards);
        auto coder = ReedSolomon::make(dataShards, parityShards);
        REQUIRE(coder);
        const std::uint32_t total = dataShards + parityShards;
        const std::size_t length = 24;
        auto pristine = randomStore(total, length, random);
        encodeStore(*coder, dataShards, parityShards, pristine);
        auto scratch = std::vector<std::byte>(*ReedSolomon::scratchBytes(dataShards, parityShards));

        for (int round = 0; round < 200; ++round) {
            const std::uint32_t missingCount =
                static_cast<std::uint32_t>(random() % (parityShards + 1));
            std::vector<std::uint32_t> missing;
            std::vector<bool> taken(total, false);
            for (std::uint32_t pick = 0; pick < missingCount; ++pick) {
                const auto shard = static_cast<std::uint32_t>(random() % total);
                if (!taken[shard]) {
                    taken[shard] = true;
                    missing.push_back(shard);
                }
            }
            CAPTURE(missingCount);
            auto work = pristine;
            CHECK(repairMissing(*coder, total, missing, work, scratch));
            CHECK(verifyStore(*coder, dataShards, parityShards, work));
            CHECK(work == pristine);
        }
    }
}

TEST_CASE("erasures past the budget refuse without touching outputs") {
    auto coder = ReedSolomon::make(4, 2);
    REQUIRE(coder);
    XorShift random;
    auto pristine = randomStore(6, 16, random);
    encodeStore(*coder, 4, 2, pristine);

    auto work = pristine;
    for (auto& shard : work) {
        for (std::byte& cell : shard) {
            cell = std::byte{0xA5};
        }
    }
    std::vector<std::span<std::byte>> shards(6);
    for (std::uint32_t shard = 0; shard < 6; ++shard) {
        shards[shard] = work[shard];
    }
    const std::uint32_t overBudget[3] = {0, 1, 2};
    auto scratch = std::vector<std::byte>(*ReedSolomon::scratchBytes(4, 2));
    auto repaired = coder->repair(shards, overBudget, scratch);
    REQUIRE_FALSE(repaired);
    CHECK(repaired.error().kind == ErrorKind::Integrity);
    for (const auto& shard : work) {
        for (const std::byte& cell : shard) {
            CHECK(cell == std::byte{0xA5});
        }
    }
}

TEST_CASE("silent corruption is detected, never silently corrected") {
    auto coder = ReedSolomon::make(4, 2);
    REQUIRE(coder);
    XorShift random;
    auto pristine = randomStore(6, 16, random);
    encodeStore(*coder, 4, 2, pristine);
    REQUIRE(verifyStore(*coder, 4, 2, pristine));

    auto tampered = pristine;
    tampered[0][3] = static_cast<std::byte>(std::to_integer<std::uint8_t>(tampered[0][3]) ^ 0xFF);
    CHECK_FALSE(verifyStore(*coder, 4, 2, tampered));

    auto tamperedParity = pristine;
    tamperedParity[5][0] =
        static_cast<std::byte>(std::to_integer<std::uint8_t>(tamperedParity[5][0]) ^ 0x01);
    CHECK_FALSE(verifyStore(*coder, 4, 2, tamperedParity));

    // NOTE: a corrupted shard marked present poisons recovery; the follow-up
    // NOTE: verify must catch it. Erasure repair trusts the flags it is given.
    auto work = tampered;
    auto scratch = std::vector<std::byte>(*ReedSolomon::scratchBytes(4, 2));
    const std::vector<std::uint32_t> missing = {1};
    CHECK(repairMissing(*coder, 6, missing, work, scratch));
    CHECK(work != pristine);
    CHECK_FALSE(verifyStore(*coder, 4, 2, work));
}

TEST_CASE("adversarial shapes fail before any allocation or work") {
    CHECK_FALSE(ReedSolomon::make(0, 1).has_value());
    CHECK_FALSE(ReedSolomon::make(1, 0).has_value());
    CHECK_FALSE(ReedSolomon::make(200, 100).has_value());
    CHECK_FALSE(ReedSolomon::make(255, 2).has_value());
    CHECK(ReedSolomon::make(255, 1).has_value());
    CHECK_FALSE(ReedSolomon::scratchBytes(0, 1).has_value());
    CHECK_FALSE(ReedSolomon::scratchBytes(1000, 1000).has_value());
    CHECK(ReedSolomon::make(200, 100).error().kind == ErrorKind::LimitExceeded);

    auto coder = ReedSolomon::make(2, 1);
    REQUIRE(coder);

    std::vector<std::byte> longA(4, std::byte{1});
    std::vector<std::byte> longB(5, std::byte{2});
    std::vector<std::span<const std::byte>> ragged = {longA, longB};
    std::vector<std::byte> parityBacking(4, std::byte{0});
    std::vector<std::span<std::byte>> parity = {parityBacking};
    CHECK_FALSE(coder->encode(ragged, parity).has_value());

    std::vector<std::byte> empty;
    std::vector<std::span<const std::byte>> emptyData = {empty, empty};
    CHECK_FALSE(coder->encode(emptyData, parity).has_value());

    std::vector<std::byte> oversized(maxShardBytes + 1, std::byte{0});
    std::vector<std::span<const std::byte>> huge = {oversized, oversized};
    std::vector<std::span<std::byte>> hugeParity;
    CHECK(coder->encode(huge, hugeParity).error().kind == ErrorKind::Malformed);
    std::vector<std::byte> hugeOut(maxShardBytes + 1, std::byte{0});
    hugeParity = {hugeOut};
    CHECK(coder->encode(huge, hugeParity).error().kind == ErrorKind::LimitExceeded);

    std::vector<std::vector<std::byte>> store(3, std::vector<std::byte>(8, std::byte{0}));
    std::vector<std::span<std::byte>> shards = {store[0], store[1], store[2]};
    std::vector<std::byte> scratch(*ReedSolomon::scratchBytes(2, 1));
    const std::uint32_t outOfRange[1] = {7};
    CHECK(coder->repair(shards, outOfRange, scratch).error().kind == ErrorKind::Malformed);
    const std::uint32_t duplicated[2] = {0, 0};
    CHECK(coder->repair(shards, duplicated, scratch).error().kind == ErrorKind::Malformed);
    std::vector<std::span<std::byte>> shortShards = {store[0], store[1]};
    const std::uint32_t none[1] = {0};
    CHECK_FALSE(
        coder->repair(shortShards, std::span<const std::uint32_t>(none, 0), scratch).has_value()
    );

    const std::uint32_t some[1] = {2};
    std::vector<std::byte> tiny(1, std::byte{0});
    CHECK(coder->repair(shards, some, tiny).error().kind == ErrorKind::LimitExceeded);
}
