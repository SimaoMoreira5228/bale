#pragma once

#include "base/error.hpp"
#include "crypto/secrets.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale::crypto {

inline constexpr std::size_t keySize = 32;
inline constexpr std::size_t nonceSize = 24;
inline constexpr std::size_t tagSize = 16;
inline constexpr std::size_t saltSize = 16;
inline constexpr std::size_t publicKeySize = 32;
inline constexpr std::size_t secretKeySize = 32;
inline constexpr std::size_t sealOverhead = 48;
inline constexpr std::size_t signSeedSize = 32;
inline constexpr std::size_t signPublicKeySize = 32;
inline constexpr std::size_t signSecretKeySize = 64;
inline constexpr std::size_t signSignatureSize = 64;

struct KdfParams {
    std::uint64_t opslimit = 0;
    std::size_t memlimitBytes = 0;
};

// NOTE: bale-level KDF ceilings for password slots. The tree only ever emits INTERACTIVE
// (opslimit 2, 64 MiB); MODERATE (3, 256 MiB) and SENSITIVE (4, 1 GiB) bound every
// foreseeable tuning level. Memory is the allocation vector, so it stops exactly at the
// SENSITIVE ceiling; ops gets 2x headroom because extra passes cost time, not allocation.
// Anything above is corrupt or hostile: the opener pays the KDF cost, so every path below
// rejects over-cap params before deriving.
inline constexpr std::uint64_t maxSlotOpslimit = 8;
inline constexpr std::size_t maxSlotMemlimitBytes = std::size_t{1} << 30;

[[nodiscard]] KdfParams interactiveKdfParams();

[[nodiscard]] KdfParams moderateKdfParams();

[[nodiscard]] Result<SecretBytes>
deriveKey(std::span<const std::byte> password, std::span<const std::byte> salt, KdfParams params);

[[nodiscard]] Result<SecretBytes> makeKey();

[[nodiscard]] Result<std::array<std::byte, nonceSize>> makeNonce();

struct BoxKeyPair {
    std::array<std::byte, publicKeySize> publicKey{};
    SecretBytes secretKey{};
};

[[nodiscard]] Result<BoxKeyPair> makeKeyPair();

[[nodiscard]] Result<std::vector<std::byte>> seal(
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> plaintext,
    std::span<const std::byte> ad
);

[[nodiscard]] Result<std::vector<std::byte>> open(
    std::span<const std::byte> key,
    std::span<const std::byte> nonce,
    std::span<const std::byte> boxed,
    std::span<const std::byte> ad
);

struct PasswordSlot {
    std::uint64_t epoch = 0;
    std::array<std::byte, saltSize> salt{};
    std::uint64_t opslimit = 0;
    std::size_t memlimitBytes = 0;
    std::array<std::byte, nonceSize> nonce{};
    std::vector<std::byte> wrapped;
};

[[nodiscard]] Result<PasswordSlot> wrapPasswordKey(
    std::span<const std::byte> key,
    std::span<const std::byte> password,
    KdfParams params,
    std::uint64_t epoch
);

[[nodiscard]] Result<SecretBytes>
unwrapPasswordKey(const PasswordSlot& slot, std::span<const std::byte> password);

struct RecipientSlot {
    std::vector<std::byte> sealed;
};

[[nodiscard]] Result<RecipientSlot>
wrapRecipientKey(std::span<const std::byte> key, std::span<const std::byte> publicKey);

[[nodiscard]] Result<SecretBytes> unwrapRecipientKey(
    const RecipientSlot& slot,
    std::span<const std::byte> publicKey,
    std::span<const std::byte> secretKey
);

[[nodiscard]] Result<std::array<std::byte, publicKeySize>>
publicKeyOf(std::span<const std::byte> secretKey);

struct SignKeyPair {
    std::array<std::byte, signPublicKeySize> publicKey{};
    SecretBytes secretKey;
};

[[nodiscard]] Result<SignKeyPair> makeSignKeyPair();

[[nodiscard]] Result<std::array<std::byte, signPublicKeySize>>
signPublicKeyOf(std::span<const std::byte> seed);

[[nodiscard]] Result<std::array<std::byte, signSignatureSize>>
signDetached(std::span<const std::byte> message, std::span<const std::byte> seed);

[[nodiscard]] Result<void> verifyDetached(
    std::span<const std::byte> signature,
    std::span<const std::byte> message,
    std::span<const std::byte> publicKey
);

}
