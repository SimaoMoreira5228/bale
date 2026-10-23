#include "crypto/secrets.hpp"

#include "crypto/crypto_vectors.hpp"

#include <doctest/doctest.h>

#include <cstddef>
#include <span>
#include <type_traits>
#include <vector>

using namespace bale;
using namespace bale::crypto;

TEST_CASE("secret storage is move-only") {
    CHECK(!std::is_copy_constructible_v<SecretBytes>);
    CHECK(!std::is_copy_assignable_v<SecretBytes>);
    CHECK(std::is_move_constructible_v<SecretBytes>);
    CHECK(std::is_move_assignable_v<SecretBytes>);
}

TEST_CASE("secret storage moves ownership") {
    auto made = SecretBytes::make(32);
    REQUIRE(made.has_value());
    SecretBytes first(std::move(*made));
    for (std::size_t at = 0; at < first.size(); ++at) {
        first.mut()[at] = static_cast<std::byte>(at);
    }

    SecretBytes second(std::move(first));
    // NOLINTNEXTLINE(bugprone-use-after-move, clang-analyzer-cplusplus.Move)
    CHECK(first.size() == 0);
    // NOLINTNEXTLINE(bugprone-use-after-move, clang-analyzer-cplusplus.Move)
    CHECK(first.bytes().empty());
    CHECK(second.size() == 32);
    CHECK(second.bytes()[3] == std::byte{3});

    SecretBytes third;
    third = std::move(second);
    // NOLINTNEXTLINE(bugprone-use-after-move, clang-analyzer-cplusplus.Move)
    CHECK(second.size() == 0);
    CHECK(third.size() == 32);
    CHECK(third.bytes()[3] == std::byte{3});
}

TEST_CASE("secret storage wipes on demand and empty secrets stay inert") {
    SUBCASE("wipe zeroes") {
        auto made = SecretBytes::make(32);
        REQUIRE(made.has_value());
        SecretBytes secret(std::move(*made));
        for (std::size_t at = 0; at < secret.size(); ++at) {
            secret.mut()[at] = static_cast<std::byte>(0xA5);
        }

        secret.wipe();

        for (std::byte value : secret.bytes()) {
            CHECK(value == std::byte{0});
        }
    }

    SUBCASE("empty stays inert") {
        SecretBytes secret;
        CHECK(secret.size() == 0);
        CHECK(secret.bytes().empty());
        CHECK(secret.mut().empty());

        secret.wipe();
        CHECK(secret.bytes().empty());

        auto made = SecretBytes::make(0);
        REQUIRE(made.has_value());
        CHECK(made->size() == 0);
        CHECK(made->bytes().empty());
    }
}
