#pragma once

#include "base/error.hpp"
#include "checksum/blake3.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale::archive {

inline constexpr std::uint64_t commitSchemaVersion = 1;
inline constexpr std::uint64_t knownCommitFeatures = 0;

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
    RecordReference manifest;
    RecordReference index;
};

[[nodiscard]] Result<void> encodeCommit(const Commit& commit, std::vector<std::byte>& out);

[[nodiscard]] Result<Commit> decodeCommit(std::span<const std::byte> payload, std::uint64_t offset);

}
