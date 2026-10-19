#include "crypto/crypto.hpp"

#include "crypto/crypto_vectors.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstddef>
#include <span>
#include <string_view>
#include <vector>

using namespace bale;
using namespace bale::crypto;

namespace {

// NOTE: AEAD_XChaCha20_Poly1305 test vector from draft-irtf-cfrg-xchacha-03,
// appendix A.3.1. Same plaintext/key/nonce triple is pinned in libsodium's own
// test/default/aead_xchacha20poly1305.c, but the expected bytes below come from
// the draft, not from running bale code.
constexpr std::string_view draftKeyHex =
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
constexpr std::string_view draftNonceHex = "404142434445464748494a4b4c4d4e4f5051525354555657";
constexpr std::string_view draftAdHex = "50515253c0c1c2c3c4c5c6c7";
constexpr std::string_view draftPlaintextHex =
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e";
constexpr std::string_view draftCiphertextHex =
    "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
    "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
    "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
    "21f9664c97637da9768812f615c68b13b52e";
constexpr std::string_view draftTagHex = "c0875924c1c7987947deafd8780acf49";

std::vector<std::byte> draftBoxed() {
    auto boxed = test::hexDecode(draftCiphertextHex);
    auto tag = test::hexDecode(draftTagHex);
    boxed.insert(boxed.end(), tag.begin(), tag.end());
    return boxed;
}

}

TEST_CASE("xchacha20-poly1305 matches the draft vector") {
    auto key = test::hexDecode(draftKeyHex);
    auto nonce = test::hexDecode(draftNonceHex);
    auto ad = test::hexDecode(draftAdHex);
    auto plaintext = test::hexDecode(draftPlaintextHex);

    auto boxed = seal(key, nonce, plaintext, ad);
    REQUIRE(boxed.has_value());
    CHECK(test::hexEncode(*boxed) == std::string(draftCiphertextHex) + std::string(draftTagHex));

    auto back = open(key, nonce, *boxed, ad);
    REQUIRE(back.has_value());
    CHECK(test::hexEncode(*back) == std::string(draftPlaintextHex));
}

TEST_CASE("xchacha20-poly1305 rejects forgeries and misuse") {
    auto key = test::hexDecode(draftKeyHex);
    auto nonce = test::hexDecode(draftNonceHex);
    auto ad = test::hexDecode(draftAdHex);
    auto boxed = draftBoxed();

    auto tamperedTag = boxed;
    tamperedTag.back() = static_cast<std::byte>(tamperedTag.back() ^ std::byte{0x01});
    CHECK(open(key, nonce, tamperedTag, ad).error().kind == ErrorKind::Integrity);

    auto tamperedBody = boxed;
    tamperedBody.front() = static_cast<std::byte>(tamperedBody.front() ^ std::byte{0x01});
    CHECK(open(key, nonce, tamperedBody, ad).error().kind == ErrorKind::Integrity);

    auto wrongKey =
        test::hexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    CHECK(open(wrongKey, nonce, boxed, ad).error().kind == ErrorKind::Integrity);

    auto wrongNonce = nonce;
    wrongNonce.front() = static_cast<std::byte>(wrongNonce.front() ^ std::byte{0x01});
    CHECK(open(key, wrongNonce, boxed, ad).error().kind == ErrorKind::Integrity);

    auto wrongAd = ad;
    wrongAd.front() = static_cast<std::byte>(wrongAd.front() ^ std::byte{0x01});
    CHECK(open(key, nonce, boxed, wrongAd).error().kind == ErrorKind::Integrity);

    auto shortBoxed = std::vector<std::byte>(boxed.begin(), boxed.begin() + tagSize - 1);
    CHECK(open(key, nonce, shortBoxed, ad).error().kind == ErrorKind::Truncated);

    auto shortKey = std::vector<std::byte>(key.begin(), key.begin() + keySize - 1);
    CHECK(seal(shortKey, nonce, boxed, ad).error().kind == ErrorKind::Malformed);
    CHECK(open(shortKey, nonce, boxed, ad).error().kind == ErrorKind::Malformed);

    auto shortNonce = std::vector<std::byte>(nonce.begin(), nonce.begin() + nonceSize - 1);
    CHECK(seal(key, shortNonce, boxed, ad).error().kind == ErrorKind::Malformed);
}

TEST_CASE("xchacha20-poly1305 round-trips fresh keys with empty inputs") {
    auto key = makeKey();
    REQUIRE(key.has_value());

    auto nonce = makeNonce();
    REQUIRE(nonce.has_value());

    std::vector<std::byte> empty;
    auto boxed = seal(key->bytes(), *nonce, empty, empty);
    REQUIRE(boxed.has_value());
    CHECK(boxed->size() == tagSize);

    auto back = open(key->bytes(), *nonce, *boxed, empty);
    REQUIRE(back.has_value());
    CHECK(back->empty());
}
