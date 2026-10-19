#include "crypto/crypto.hpp"

#include "crypto/crypto_vectors.hpp"

#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_pwhash_argon2id.h>

#include <doctest/doctest.h>

#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

using namespace bale;
using namespace bale::crypto;

namespace {

// NOTE: all three strings below are known-answer vectors from libsodium's own
// test suite (test/default/pwhash_argon2id.c tv3, 1.0.20-stable), generated
// against the argon2 reference code. They pin the Argon2id path bale's reduced
// build carries; bale never invents KDF outputs.
struct McfVector {
    std::string_view password;
    std::string_view hash;
};

constexpr McfVector mcfVectors[] = {
    {
        "",
        "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+"
        "7RH1DXo9rvp5cwKEOOOfD2g6JuxlXihoNcpE",
    },
    {
        "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg ",
        "$argon2id$v=19$m=4096,t=19,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/"
        "ue1kPtBMBGfsysMpPigE6hiNEKZ9vs8vLNVDQGA",
    },
    {
        "K3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*",
        "$argon2id$v=19$m=4096,t=1,p=3$PkEgcHJldHR5IGxvbmcgc2FsdA$HUqx5Z1b/"
        "ZypnUrvvJ5UC2Q+T6Q1WwASK/Kr9dRbGA0",
    },
};

constexpr std::size_t smallMemBytes = 32768;

}

TEST_CASE("argon2id verifies upstream known-answer strings") {
    for (const auto& vector : mcfVectors) {
        CAPTURE(vector.hash);

        std::string password(vector.password);
        std::string hash(vector.hash);

        int done = crypto_pwhash_str_verify(
            hash.c_str(),
            password.c_str(),
            static_cast<unsigned long long>(password.size())
        );
        CHECK(done == 0);

        std::string wrong = password + "x";
        int refused = crypto_pwhash_str_verify(
            hash.c_str(),
            wrong.c_str(),
            static_cast<unsigned long long>(wrong.size())
        );
        CHECK(refused != 0);
    }
}

TEST_CASE("argon2id derivation is deterministic and input-sensitive") {
    KdfParams params{.opslimit = 1, .memlimitBytes = smallMemBytes};

    auto salt = test::hexDecode("000102030405060708090a0b0c0d0e0f");
    std::vector<std::byte> password{
        std::byte{'s'},
        std::byte{'e'},
        std::byte{'c'},
        std::byte{'r'},
        std::byte{'e'},
        std::byte{'t'}
    };

    auto first = deriveKey(password, salt, params);
    REQUIRE(first.has_value());

    auto second = deriveKey(password, salt, params);
    REQUIRE(second.has_value());
    CHECK(test::hexEncode(first->bytes()) == test::hexEncode(second->bytes()));

    std::vector<std::byte> otherPassword(password.begin(), password.end());
    otherPassword.back() = std::byte{'x'};
    auto other = deriveKey(otherPassword, salt, params);
    REQUIRE(other.has_value());
    CHECK(test::hexEncode(first->bytes()) != test::hexEncode(other->bytes()));

    auto otherSalt = salt;
    otherSalt.back() = static_cast<std::byte>(otherSalt.back() ^ std::byte{0x01});
    auto salted = deriveKey(password, otherSalt, params);
    REQUIRE(salted.has_value());
    CHECK(test::hexEncode(first->bytes()) != test::hexEncode(salted->bytes()));

    KdfParams otherParams{.opslimit = 2, .memlimitBytes = smallMemBytes};
    auto tuned = deriveKey(password, salt, otherParams);
    REQUIRE(tuned.has_value());
    CHECK(test::hexEncode(first->bytes()) != test::hexEncode(tuned->bytes()));
}

TEST_CASE("argon2id derivation rejects out-of-range parameters") {
    KdfParams params{.opslimit = 1, .memlimitBytes = smallMemBytes};

    auto salt = test::hexDecode("000102030405060708090a0b0c0d0e0f");
    std::vector<std::byte> password{std::byte{'p'}, std::byte{'w'}};

    auto shortSalt = std::vector<std::byte>(salt.begin(), salt.begin() + saltSize - 1);
    CHECK(deriveKey(password, shortSalt, params).error().kind == ErrorKind::Malformed);

    KdfParams noOps{.opslimit = 0, .memlimitBytes = smallMemBytes};
    CHECK(deriveKey(password, salt, noOps).error().kind == ErrorKind::Malformed);

    KdfParams noMem{.opslimit = 1, .memlimitBytes = 0};
    CHECK(deriveKey(password, salt, noMem).error().kind == ErrorKind::Malformed);
}
