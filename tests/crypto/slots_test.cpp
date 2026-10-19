#include "crypto/crypto.hpp"

#include "crypto/crypto_vectors.hpp"

#include <doctest/doctest.h>

#include <cstddef>
#include <span>
#include <vector>

using namespace bale;
using namespace bale::crypto;

namespace {

constexpr std::uint64_t testOps = 1;
constexpr std::size_t testMemBytes = 32768;

KdfParams testParams() {
    return {.opslimit = testOps, .memlimitBytes = testMemBytes};
}

std::vector<std::byte> testPassword() {
    return {
        std::byte{'p'},
        std::byte{'a'},
        std::byte{'s'},
        std::byte{'s'},
        std::byte{'w'},
        std::byte{'o'},
        std::byte{'r'},
        std::byte{'d'}
    };
}

}

TEST_CASE("password slots wrap and unwrap the data key") {
    auto dataKey = makeKey();
    REQUIRE(dataKey.has_value());

    auto slot = wrapPasswordKey(dataKey->bytes(), testPassword(), testParams());
    REQUIRE(slot.has_value());
    CHECK(slot->wrapped.size() == keySize + tagSize);

    auto back = unwrapPasswordKey(*slot, testPassword());
    REQUIRE(back.has_value());
    CHECK(test::hexEncode(back->bytes()) == test::hexEncode(dataKey->bytes()));
}

TEST_CASE("password slots reject wrong passwords and damage") {
    auto dataKey = makeKey();
    REQUIRE(dataKey.has_value());

    auto slot = wrapPasswordKey(dataKey->bytes(), testPassword(), testParams());
    REQUIRE(slot.has_value());

    auto wrong = testPassword();
    wrong.back() = std::byte{'x'};
    auto refused = unwrapPasswordKey(*slot, wrong);
    REQUIRE(!refused.has_value());
    CHECK(refused.error().kind == ErrorKind::Integrity);

    auto damaged = *slot;
    damaged.wrapped.front() = static_cast<std::byte>(damaged.wrapped.front() ^ std::byte{0x01});
    auto broken = unwrapPasswordKey(damaged, testPassword());
    REQUIRE(!broken.has_value());
    CHECK(broken.error().kind == ErrorKind::Integrity);

    auto shortSlot = *slot;
    shortSlot.wrapped.pop_back();
    CHECK(unwrapPasswordKey(shortSlot, testPassword()).error().kind == ErrorKind::Malformed);
}

TEST_CASE("password slots work at minimum memory") {
    auto dataKey = makeKey();
    REQUIRE(dataKey.has_value());

    KdfParams floor{.opslimit = 1, .memlimitBytes = 8192};
    auto slot = wrapPasswordKey(dataKey->bytes(), testPassword(), floor);
    REQUIRE(slot.has_value());

    auto back = unwrapPasswordKey(*slot, testPassword());
    REQUIRE(back.has_value());
    CHECK(test::hexEncode(back->bytes()) == test::hexEncode(dataKey->bytes()));
}

TEST_CASE("recipient slots wrap and unwrap for one keypair") {
    auto dataKey = makeKey();
    REQUIRE(dataKey.has_value());

    auto pair = makeKeyPair();
    REQUIRE(pair.has_value());

    auto slot = wrapRecipientKey(dataKey->bytes(), pair->publicKey);
    REQUIRE(slot.has_value());
    CHECK(slot->sealed.size() == keySize + sealOverhead);

    auto back = unwrapRecipientKey(*slot, pair->publicKey, pair->secretKey.bytes());
    REQUIRE(back.has_value());
    CHECK(test::hexEncode(back->bytes()) == test::hexEncode(dataKey->bytes()));
}

TEST_CASE("recipient slots reject the wrong key and damage") {
    auto dataKey = makeKey();
    REQUIRE(dataKey.has_value());

    auto pair = makeKeyPair();
    REQUIRE(pair.has_value());

    auto other = makeKeyPair();
    REQUIRE(other.has_value());

    auto slot = wrapRecipientKey(dataKey->bytes(), pair->publicKey);
    REQUIRE(slot.has_value());

    auto refused = unwrapRecipientKey(*slot, other->publicKey, other->secretKey.bytes());
    REQUIRE(!refused.has_value());
    CHECK(refused.error().kind == ErrorKind::Integrity);

    auto damaged = *slot;
    damaged.sealed.front() = static_cast<std::byte>(damaged.sealed.front() ^ std::byte{0x01});
    auto broken = unwrapRecipientKey(damaged, pair->publicKey, pair->secretKey.bytes());
    REQUIRE(!broken.has_value());
    CHECK(broken.error().kind == ErrorKind::Integrity);

    auto shortSlot = *slot;
    shortSlot.sealed.pop_back();
    auto malformed = unwrapRecipientKey(shortSlot, pair->publicKey, pair->secretKey.bytes());
    CHECK(malformed.error().kind == ErrorKind::Malformed);

    auto shortKey = std::vector<std::byte>(pair->publicKey.begin(), pair->publicKey.end() - 1);
    CHECK(wrapRecipientKey(dataKey->bytes(), shortKey).error().kind == ErrorKind::Malformed);
}
