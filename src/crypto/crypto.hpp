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

struct KdfParams {
    std::uint64_t opslimit = 0;
    std::size_t memlimitBytes = 0;
};

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
    std::array<std::byte, saltSize> salt{};
    std::uint64_t opslimit = 0;
    std::size_t memlimitBytes = 0;
    std::array<std::byte, nonceSize> nonce{};
    std::vector<std::byte> wrapped;
};

[[nodiscard]] Result<PasswordSlot> wrapPasswordKey(
    std::span<const std::byte> key,
    std::span<const std::byte> password,
    KdfParams params
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

}
