#pragma once

#include "base/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace bale::archive {

enum class CdcAlgorithm : std::uint8_t {
    Gear = 1,
};

struct CdcParams {
    std::uint32_t min = 0;
    std::uint32_t target = 0;
    std::uint32_t max = 0;
};

inline constexpr std::uint32_t cdcMinDefault = 256 * 1024;
inline constexpr std::uint32_t cdcTargetDefault = 1024 * 1024;
inline constexpr std::uint32_t cdcMaxDefault = 4 * 1024 * 1024;

inline constexpr CdcParams defaultCdcParams{
    .min = cdcMinDefault,
    .target = cdcTargetDefault,
    .max = cdcMaxDefault,
};

// NOTE: the gear table below is pinned. The seed is part of the chunking policy: changing it
// re-cuts every archive, so it only ever changes behind a new CdcAlgorithm id.
inline constexpr std::uint64_t cdcTableSeed = 0x243F6A8885A308D3ULL;

constexpr std::uint64_t splitmix64Step(std::uint64_t value) {
    std::uint64_t merged = value + 0x9E3779B97F4A7C15ULL;

    merged = (merged ^ (merged >> 30)) * 0xBF58476D1CE4E5B9ULL;
    merged = (merged ^ (merged >> 27)) * 0x94D049BB133111EBULL;
    return merged ^ (merged >> 31);
}

constexpr std::array<std::uint64_t, 256> makeGearTable() {
    std::array<std::uint64_t, 256> table{};

    std::uint64_t state = cdcTableSeed;
    for (std::size_t index = 0; index < table.size(); ++index) {
        state = splitmix64Step(state);
        table[index] = state;
    }
    return table;
}

inline constexpr std::array<std::uint64_t, 256> gearTable = makeGearTable();

[[nodiscard]] Result<void> validateCdcParams(const CdcParams& params);

class CdcSplitter {
  public:
    explicit CdcSplitter(const CdcParams& params = defaultCdcParams);

    void reset();
    void nextChunk();

    [[nodiscard]] bool feed(std::byte value);
    [[nodiscard]] std::uint32_t length() const;

  private:
    CdcParams params_;
    std::uint64_t hash_ = 0;
    std::uint32_t length_ = 0;
    std::uint64_t mask_ = 0;
    bool masked_ = false;
};

inline bool CdcSplitter::feed(std::byte value) {
    std::uint64_t mixed = (hash_ << 1) + gearTable[static_cast<unsigned char>(value)];
    hash_ = mixed;

    ++length_;
    if (length_ >= params_.max) {
        return true;
    }
    if (length_ < params_.min) {
        return false;
    }
    if (masked_) {
        return (hash_ & mask_) == 0;
    }
    return hash_ % params_.target == 0;
}

inline std::uint32_t CdcSplitter::length() const {
    return length_;
}

}
