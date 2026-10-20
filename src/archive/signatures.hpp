#pragma once

#include "base/error.hpp"
#include "crypto/crypto.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale::archive {

// NOTE: all numeric wire values below are provisional experimental allocations. The native
// NOTE: format is unfrozen; later builds may not read archives using them.

inline constexpr std::uint32_t signatureExtensionKind = 2;
inline constexpr std::uint64_t signatureVersion = 1;
inline constexpr std::size_t signerIdSize = crypto::signPublicKeySize;
inline constexpr std::size_t signatureSize = crypto::signSignatureSize;
inline constexpr std::uint64_t maxSignaturesPerCommit = 16;
inline constexpr std::uint64_t maxSignaturePayloadBytes = 512;

struct Signature {
    std::uint64_t epoch = 0;
    std::array<std::byte, signerIdSize> signer{};
    std::array<std::byte, signatureSize> signature{};
};

[[nodiscard]] Result<void> encodeSignature(const Signature& signature, std::vector<std::byte>& out);

[[nodiscard]] Result<Signature>
decodeSignature(std::span<const std::byte> payload, std::uint64_t offset);

[[nodiscard]] Result<std::uint32_t>
peekExtensionKind(std::span<const std::byte> payload, std::uint64_t offset);

[[nodiscard]] std::vector<std::byte> signatureMessage(
    std::span<const std::byte, 16> archiveId,
    std::uint64_t generation,
    std::uint64_t epoch,
    std::span<const std::byte, 32> commitDigest
);

[[nodiscard]] Result<Signature> makeSignature(
    std::span<const std::byte> seed,
    std::span<const std::byte, 16> archiveId,
    std::uint64_t generation,
    std::uint64_t epoch,
    std::span<const std::byte, 32> commitDigest
);

[[nodiscard]] Result<void> checkSignature(
    const Signature& signature,
    std::span<const std::byte> publicKey,
    std::span<const std::byte, 16> archiveId,
    std::uint64_t generation,
    std::uint64_t epoch,
    std::span<const std::byte, 32> commitDigest
);

}
