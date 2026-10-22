#pragma once

#include "base/error.hpp"
#include "format/envelope.hpp"
#include "parity/reed_solomon.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace bale::archive {

// NOTE: all numeric wire values below are provisional experimental allocations. The native
// NOTE: format is unfrozen; later builds may not read archives using them.

inline constexpr std::uint32_t parityRecordVersion = 1;
inline constexpr std::uint32_t defaultParityShardBytes = std::uint32_t{64} << 10;
inline constexpr std::uint32_t minParityShardBytes = std::uint32_t{1} << 10;
inline constexpr std::uint32_t maxParityShardBytes = std::uint32_t{1} << 20;
inline constexpr std::uint64_t maxParityStripeBytes = std::uint64_t{256} << 20;

struct ParityConfig {
    bool enabled = false;
    std::uint32_t dataShards = 10;
    std::uint32_t parityShards = 4;
    std::uint32_t shardBytes = defaultParityShardBytes;
};

struct ParityHeader {
    std::uint64_t groupId = 0;
    std::uint64_t generation = 0;
    std::uint64_t stripeIndex = 0;
    std::uint32_t shardIndex = 0;
    std::uint32_t dataShards = 0;
    std::uint32_t parityShards = 0;
    std::uint32_t shardBytes = 0;
    std::uint64_t stripeCount = 0;
    std::uint64_t streamLength = 0;
    std::vector<std::uint32_t> crc;
};

[[nodiscard]] Result<ParityConfig> parseParitySpec(std::string_view text);

[[nodiscard]] Result<void> validateParityConfig(const ParityConfig& config);

[[nodiscard]] Result<std::uint64_t>
stripeCountFor(std::uint64_t streamLength, std::uint32_t dataShards, std::uint32_t shardBytes);

[[nodiscard]] Result<ParityDescriptor>
makeParityDescriptor(const ParityConfig& config, std::uint64_t streamLength, std::uint64_t groupId);

[[nodiscard]] constexpr std::size_t parityHeaderLength(std::uint32_t totalShards) {
    return 60 + static_cast<std::size_t>(totalShards) * sizeof(std::uint32_t);
}

inline constexpr std::uint64_t maxParityRecordPayload =
    static_cast<std::uint64_t>(60 + 256 * sizeof(std::uint32_t)) +
    static_cast<std::uint64_t>(bale::parity::maxShardBytes);

[[nodiscard]] Result<void> encodeParityRecord(
    const ParityHeader& header,
    std::span<const std::byte> shard,
    std::vector<std::byte>& out
);

[[nodiscard]] Result<ParityHeader>
decodeParityRecord(std::span<const std::byte> payload, std::uint64_t offset);

[[nodiscard]] Result<void> checkParityHeader(
    const ParityHeader& header,
    const ParityDescriptor& descriptor,
    std::uint64_t generation,
    std::uint64_t offset
);

}
