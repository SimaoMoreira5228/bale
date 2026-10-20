#pragma once

#include "base/error.hpp"
#include "checksum/blake3.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale::archive {

inline constexpr std::uint64_t commitSchemaVersion = 1;
// NOTE: provisional experimental ENCRYPTED value; later builds may not read archives using it.
inline constexpr std::uint64_t encryptedCommitFeature = 0x00000001;
// NOTE: provisional experimental PARITY value; later builds may not read archives using it.
inline constexpr std::uint64_t parityCommitFeature = 0x00000002;
inline constexpr std::uint64_t knownCommitFeatures = encryptedCommitFeature | parityCommitFeature;

struct RecordReference {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    Blake3Digest digest{};
};

struct Commit {
    std::uint64_t generation = 1;
    Blake3Digest previous{};
    std::uint64_t previousFooterOffset = 0;
    std::uint64_t requiredFeatures = 0;
    std::uint64_t epoch = 0;
    RecordReference manifest;
    RecordReference index;
};

[[nodiscard]] Result<void> encodeCommit(const Commit& commit, std::vector<std::byte>& out);

[[nodiscard]] Result<Commit> decodeCommit(std::span<const std::byte> payload, std::uint64_t offset);

}
