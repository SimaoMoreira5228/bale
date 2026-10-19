#include "crypto/crypto.hpp"

#include "base/checked.hpp"

#include <sodium/core.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_pwhash.h>
#include <sodium/crypto_pwhash_argon2id.h>
#include <sodium/crypto_scalarmult.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>

#include <algorithm>
#include <mutex>
#include <string_view>

namespace bale::crypto {

namespace {

static_assert(keySize == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(nonceSize == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(tagSize == crypto_aead_xchacha20poly1305_ietf_ABYTES);
static_assert(saltSize == crypto_pwhash_SALTBYTES);
static_assert(publicKeySize == crypto_box_PUBLICKEYBYTES);
static_assert(secretKeySize == crypto_box_SECRETKEYBYTES);
static_assert(sealOverhead == crypto_box_SEALBYTES);

constexpr std::string_view passwordSlotAad = "bale-crypto-v1/password-slot";

std::once_flag sodiumInitFlag;
int sodiumInitStatus = -1;

void runSodiumInit() {
    sodiumInitStatus = sodium_init();
}

Result<void> ensureInit() {
    std::call_once(sodiumInitFlag, runSodiumInit);

    if (sodiumInitStatus < 0) {
        return fail(ErrorKind::Io, "libsodium init failed", 0);
    }
    return {};
}

const unsigned char* bytesOrDummy(std::span<const std::byte> span) {
    static constexpr std::byte dummy{0};

    if (span.empty()) {
        return reinterpret_cast<const unsigned char*>(&dummy);
    }
    return reinterpret_cast<const unsigned char*>(span.data());
}

unsigned char* bytesOrDummy(std::span<std::byte> span) {
    static std::byte dummy{0};

    if (span.empty()) {
        return reinterpret_cast<unsigned char*>(&dummy);
    }
    return reinterpret_cast<unsigned char*>(span.data());
}

void randomFill(std::span<std::byte> span) {
    randombytes_buf(bytesOrDummy(span), span.size());
}

Result<void> requireSize(std::span<const std::byte> span, std::size_t want, std::string_view what) {
    if (span.size() != want) {
        return fail(ErrorKind::Malformed, what, span.size());
    }
    return {};
}

}

KdfParams interactiveKdfParams() {
    return {
        .opslimit = crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
        .memlimitBytes = crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE,
    };
}

KdfParams moderateKdfParams() {
    return {
        .opslimit = crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
        .memlimitBytes = crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
    };
}

Result<SecretBytes>
deriveKey(std::span<const std::byte> password, std::span<const std::byte> salt, KdfParams params) {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }

    if (auto sized = requireSize(salt, saltSize, "kdf salt must hold 16 bytes"); !sized) {
        return std::unexpected(sized.error());
    }

    if (params.opslimit < crypto_pwhash_argon2id_opslimit_min() ||
        params.opslimit > crypto_pwhash_argon2id_opslimit_max()) {
        return fail(ErrorKind::Malformed, "argon2id opslimit out of range", params.opslimit);
    }

    if (params.memlimitBytes < crypto_pwhash_argon2id_memlimit_min() ||
        params.memlimitBytes > crypto_pwhash_argon2id_memlimit_max()) {
        return fail(ErrorKind::Malformed, "argon2id memlimit out of range", params.memlimitBytes);
    }

    auto made = SecretBytes::make(keySize);
    if (!made) {
        return std::unexpected(made.error());
    }
    SecretBytes key(std::move(*made));

    int done = crypto_pwhash_argon2id(
        bytesOrDummy(key.mut()),
        static_cast<unsigned long long>(key.size()),
        reinterpret_cast<const char*>(bytesOrDummy(password)),
        static_cast<unsigned long long>(password.size()),
        bytesOrDummy(salt),
        static_cast<unsigned long long>(params.opslimit),
        params.memlimitBytes,
        crypto_pwhash_argon2id_ALG_ARGON2ID13
    );
    if (done != 0) {
        return fail(ErrorKind::Io, "argon2id derivation failed", 0);
    }
    return key;
}

Result<SecretBytes> makeKey() {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }

    auto made = SecretBytes::make(keySize);
    if (!made) {
        return std::unexpected(made.error());
    }
    SecretBytes key(std::move(*made));
    randomFill(key.mut());
    return key;
}

Result<std::array<std::byte, nonceSize>> makeNonce() {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }

    std::array<std::byte, nonceSize> nonce{};
    randomFill(nonce);
    return nonce;
}

Result<BoxKeyPair> makeKeyPair() {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }

    BoxKeyPair pair;

    auto made = SecretBytes::make(secretKeySize);
    if (!made) {
        return std::unexpected(made.error());
    }
    SecretBytes secret(std::move(*made));
    randomFill(secret.mut());
    pair.secretKey = std::move(secret);

    crypto_box_keypair(
        reinterpret_cast<unsigned char*>(pair.publicKey.data()),
        bytesOrDummy(pair.secretKey.mut())
    );
    return pair;
}

Result<std::array<std::byte, publicKeySize>> publicKeyOf(std::span<const std::byte> secretKey) {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }
    if (auto sized = requireSize(secretKey, secretKeySize, "recipient key must hold 32 bytes");
        !sized) {
        return std::unexpected(sized.error());
    }
    std::array<std::byte, publicKeySize> publicKey{};
    crypto_scalarmult_base(
        reinterpret_cast<unsigned char*>(publicKey.data()),
        bytesOrDummy(secretKey)
    );
    return publicKey;
}

Result<std::vector<std::byte>> seal(
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> plaintext,
    std::span<const std::byte> ad
) {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }

    if (auto sized = requireSize(key, keySize, "aead key must hold 32 bytes"); !sized) {
        return std::unexpected(sized.error());
    }

    if (auto sized = requireSize(nonce, nonceSize, "aead nonce must hold 24 bytes"); !sized) {
        return std::unexpected(sized.error());
    }

    auto boxedSize = checkedAdd(plaintext.size(), tagSize);
    if (!boxedSize) {
        return fail(ErrorKind::LimitExceeded, "plaintext too long to seal", plaintext.size());
    }

    std::vector<std::byte> boxed(*boxedSize);

    int done = crypto_aead_xchacha20poly1305_ietf_encrypt(
        bytesOrDummy(std::span<std::byte>(boxed)),
        nullptr,
        bytesOrDummy(plaintext),
        static_cast<unsigned long long>(plaintext.size()),
        bytesOrDummy(ad),
        static_cast<unsigned long long>(ad.size()),
        nullptr,
        bytesOrDummy(nonce),
        bytesOrDummy(key)
    );
    if (done != 0) {
        return fail(ErrorKind::LimitExceeded, "plaintext too long to seal", plaintext.size());
    }
    return boxed;
}

Result<std::vector<std::byte>> open(
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> boxed,
    std::span<const std::byte> ad
) {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }

    if (auto sized = requireSize(key, keySize, "aead key must hold 32 bytes"); !sized) {
        return std::unexpected(sized.error());
    }

    if (auto sized = requireSize(nonce, nonceSize, "aead nonce must hold 24 bytes"); !sized) {
        return std::unexpected(sized.error());
    }

    if (boxed.size() < tagSize) {
        return fail(ErrorKind::Truncated, "ciphertext shorter than tag", boxed.size());
    }

    std::vector<std::byte> plaintext(boxed.size() - tagSize);

    int done = crypto_aead_xchacha20poly1305_ietf_decrypt(
        bytesOrDummy(std::span<std::byte>(plaintext)),
        nullptr,
        nullptr,
        bytesOrDummy(boxed),
        static_cast<unsigned long long>(boxed.size()),
        bytesOrDummy(ad),
        static_cast<unsigned long long>(ad.size()),
        bytesOrDummy(nonce),
        bytesOrDummy(key)
    );
    if (done != 0) {
        if (!plaintext.empty()) {
            sodium_memzero(plaintext.data(), plaintext.size());
        }
        plaintext.clear();
        return fail(ErrorKind::Integrity, "aead authentication failed", 0);
    }
    return plaintext;
}

Result<PasswordSlot> wrapPasswordKey(
    std::span<const std::byte> key,
    std::span<const std::byte> password,
    KdfParams params
) {
    if (auto sized = requireSize(key, keySize, "data key must hold 32 bytes"); !sized) {
        return std::unexpected(sized.error());
    }

    PasswordSlot slot;
    slot.opslimit = params.opslimit;
    slot.memlimitBytes = params.memlimitBytes;

    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }
    randomFill(slot.salt);
    randomFill(slot.nonce);

    auto stretched = deriveKey(password, slot.salt, params);
    if (!stretched) {
        return std::unexpected(stretched.error());
    }

    std::span<const std::byte> ad(
        reinterpret_cast<const std::byte*>(passwordSlotAad.data()),
        passwordSlotAad.size()
    );
    auto wrapped = seal(stretched->bytes(), slot.nonce, key, ad);
    if (!wrapped) {
        return std::unexpected(wrapped.error());
    }
    slot.wrapped = std::move(*wrapped);
    return slot;
}

Result<SecretBytes>
unwrapPasswordKey(const PasswordSlot& slot, std::span<const std::byte> password) {
    if (slot.wrapped.size() != keySize + tagSize) {
        return fail(
            ErrorKind::Malformed,
            "password slot has a bad wrapped size",
            slot.wrapped.size()
        );
    }

    KdfParams params{
        .opslimit = slot.opslimit,
        .memlimitBytes = slot.memlimitBytes,
    };
    auto stretched = deriveKey(password, slot.salt, params);
    if (!stretched) {
        return std::unexpected(stretched.error());
    }

    std::span<const std::byte> ad(
        reinterpret_cast<const std::byte*>(passwordSlotAad.data()),
        passwordSlotAad.size()
    );
    auto key = open(stretched->bytes(), slot.nonce, slot.wrapped, ad);
    if (!key) {
        return std::unexpected(key.error());
    }

    auto made = SecretBytes::make(key->size());
    if (!made) {
        sodium_memzero(key->data(), key->size());
        return std::unexpected(made.error());
    }
    SecretBytes out(std::move(*made));
    std::ranges::copy(*key, out.mut().begin());
    sodium_memzero(key->data(), key->size());
    return out;
}

Result<RecipientSlot>
wrapRecipientKey(std::span<const std::byte> key, std::span<const std::byte> publicKey) {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }

    if (auto sized = requireSize(key, keySize, "data key must hold 32 bytes"); !sized) {
        return std::unexpected(sized.error());
    }

    if (auto sized = requireSize(publicKey, publicKeySize, "recipient key must hold 32 bytes");
        !sized) {
        return std::unexpected(sized.error());
    }

    RecipientSlot slot;
    slot.sealed.resize(keySize + sealOverhead);

    int done = crypto_box_seal(
        bytesOrDummy(std::span<std::byte>(slot.sealed)),
        bytesOrDummy(key),
        static_cast<unsigned long long>(key.size()),
        bytesOrDummy(publicKey)
    );
    if (done != 0) {
        return fail(ErrorKind::Io, "sealed box wrap failed", 0);
    }
    return slot;
}

Result<SecretBytes> unwrapRecipientKey(
    const RecipientSlot& slot,
    std::span<const std::byte> publicKey,
    std::span<const std::byte> secretKey
) {
    if (auto init = ensureInit(); !init) {
        return std::unexpected(init.error());
    }

    if (slot.sealed.size() != keySize + sealOverhead) {
        return fail(
            ErrorKind::Malformed,
            "recipient slot has a bad sealed size",
            slot.sealed.size()
        );
    }

    if (auto sized = requireSize(publicKey, publicKeySize, "recipient key must hold 32 bytes");
        !sized) {
        return std::unexpected(sized.error());
    }

    if (auto sized = requireSize(secretKey, secretKeySize, "recipient key must hold 32 bytes");
        !sized) {
        return std::unexpected(sized.error());
    }

    auto made = SecretBytes::make(keySize);
    if (!made) {
        return std::unexpected(made.error());
    }
    SecretBytes key(std::move(*made));

    int done = crypto_box_seal_open(
        bytesOrDummy(key.mut()),
        bytesOrDummy(slot.sealed),
        static_cast<unsigned long long>(slot.sealed.size()),
        bytesOrDummy(publicKey),
        bytesOrDummy(secretKey)
    );
    if (done != 0) {
        return fail(ErrorKind::Integrity, "sealed box authentication failed", 0);
    }
    return key;
}

}
