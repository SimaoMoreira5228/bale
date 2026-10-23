#include "archive/parity.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "parity/reed_solomon.hpp"

#include <algorithm>

namespace bale::archive {

namespace {

constexpr std::size_t versionAt = 0;
constexpr std::size_t groupAt = 4;
constexpr std::size_t generationAt = 12;
constexpr std::size_t stripeAt = 20;
constexpr std::size_t shardAt = 28;
constexpr std::size_t dataShardsAt = 32;
constexpr std::size_t parityShardsAt = 36;
constexpr std::size_t shardBytesAt = 40;
constexpr std::size_t stripeCountAt = 44;
constexpr std::size_t streamLengthAt = 52;
constexpr std::size_t crcTableAt = 60;
constexpr std::size_t headerBaseLength = crcTableAt;

Result<ParityConfig> explicitSpec(std::string_view text) {
    auto plus = text.find('+');
    if (plus == std::string_view::npos) {
        return fail(ErrorKind::Malformed, "parity needs <k>+<m>, small or capacity");
    }
    auto parsePart = [](std::string_view part) -> Result<std::uint32_t> {
        if (part.empty() || part.size() > 3) {
            return fail(ErrorKind::Malformed, "parity shard count is not a small integer");
        }
        std::uint32_t value = 0;
        for (char digit : part) {
            if (digit < '0' || digit > '9') {
                return fail(ErrorKind::Malformed, "parity shard count is not a small integer");
            }
            value = value * 10 + static_cast<std::uint32_t>(digit - '0');
        }
        return value;
    };
    auto data = parsePart(text.substr(0, plus));
    if (!data) {
        return tl::unexpected<Error>(data.error());
    }
    auto parity = parsePart(text.substr(plus + 1));
    if (!parity) {
        return tl::unexpected<Error>(parity.error());
    }
    ParityConfig config;
    config.enabled = true;
    config.dataShards = *data;
    config.parityShards = *parity;
    return config;
}

}

Result<ParityConfig> parseParitySpec(std::string_view text) {
    if (text == "small") {
        ParityConfig config;
        config.enabled = true;
        config.dataShards = 10;
        config.parityShards = 4;
        return config;
    }
    if (text == "capacity") {
        ParityConfig config;
        config.enabled = true;
        config.dataShards = 17;
        config.parityShards = 3;
        return config;
    }
    return explicitSpec(text);
}

Result<void> validateParityConfig(const ParityConfig& config) {
    if (!config.enabled) {
        return {};
    }
    if (config.dataShards == 0 || config.parityShards == 0) {
        return fail(ErrorKind::Malformed, "parity needs at least one data and one parity shard");
    }
    auto total = checkedAdd(config.dataShards, config.parityShards);
    if (!total || *total > 256) {
        return fail(ErrorKind::LimitExceeded, "parity shard count exceeds the field order");
    }
    if (config.shardBytes < minParityShardBytes || config.shardBytes > maxParityShardBytes) {
        return fail(ErrorKind::LimitExceeded, "parity shard size outside the writer range");
    }
    auto stripe = checkedMul(
        static_cast<std::uint64_t>(*total),
        static_cast<std::uint64_t>(config.shardBytes)
    );
    if (!stripe || *stripe > maxParityStripeBytes) {
        return fail(ErrorKind::LimitExceeded, "parity stripe working set exceeds the budget");
    }
    return {};
}

Result<std::uint64_t>
stripeCountFor(std::uint64_t streamLength, std::uint32_t dataShards, std::uint32_t shardBytes) {
    if (streamLength == 0) {
        return fail(ErrorKind::Malformed, "parity stripe stream must not be empty");
    }
    if (dataShards == 0 || shardBytes == 0) {
        return fail(ErrorKind::Malformed, "parity stripe geometry is degenerate");
    }
    auto perStripe =
        checkedMul(static_cast<std::uint64_t>(dataShards), static_cast<std::uint64_t>(shardBytes));
    if (!perStripe) {
        return fail(ErrorKind::LimitExceeded, "parity stripe size overflows");
    }
    return (streamLength + *perStripe - 1) / *perStripe;
}

Result<ParityDescriptor> makeParityDescriptor(
    const ParityConfig& config,
    std::uint64_t streamLength,
    std::uint64_t groupId
) {
    auto valid = validateParityConfig(config);
    if (!valid) {
        return tl::unexpected<Error>(valid.error());
    }
    if (groupId == 0) {
        return fail(ErrorKind::Malformed, "parity group id must not be zero");
    }
    auto stripes = stripeCountFor(streamLength, config.dataShards, config.shardBytes);
    if (!stripes) {
        return tl::unexpected<Error>(stripes.error());
    }
    ParityDescriptor descriptor;
    descriptor.present = true;
    descriptor.dataShards = config.dataShards;
    descriptor.parityShards = config.parityShards;
    descriptor.shardBytes = config.shardBytes;
    descriptor.stripeCount = *stripes;
    descriptor.groupId = groupId;
    return descriptor;
}

Result<void> encodeParityRecord(
    const ParityHeader& header,
    std::span<const std::byte> shard,
    std::vector<std::byte>& out
) {
    auto total = checkedAdd(header.dataShards, header.parityShards);
    if (!total || *total > 256) {
        return fail(ErrorKind::LimitExceeded, "parity shard count exceeds the field order");
    }
    if (header.crc.size() != *total) {
        return fail(ErrorKind::Malformed, "parity crc table does not cover every shard");
    }
    if (header.shardIndex < header.dataShards || header.shardIndex >= *total) {
        return fail(ErrorKind::Malformed, "parity shard index is not a parity shard");
    }
    if (header.shardBytes == 0 || shard.size() != header.shardBytes) {
        return fail(ErrorKind::Malformed, "parity shard does not match the declared size");
    }
    if (header.stripeIndex >= header.stripeCount) {
        return fail(ErrorKind::Malformed, "parity stripe index exceeds the stripe count");
    }
    out.clear();
    out.resize(parityHeaderLength(*total) + shard.size());
    storeLe(out.data() + versionAt, parityRecordVersion);
    storeLe(out.data() + groupAt, header.groupId);
    storeLe(out.data() + generationAt, header.generation);
    storeLe(out.data() + stripeAt, header.stripeIndex);
    storeLe(out.data() + shardAt, header.shardIndex);
    storeLe(out.data() + dataShardsAt, header.dataShards);
    storeLe(out.data() + parityShardsAt, header.parityShards);
    storeLe(out.data() + shardBytesAt, header.shardBytes);
    storeLe(out.data() + stripeCountAt, header.stripeCount);
    storeLe(out.data() + streamLengthAt, header.streamLength);
    for (std::uint32_t index = 0; index < *total; ++index) {
        storeLe(out.data() + crcTableAt + index * sizeof(std::uint32_t), header.crc[index]);
    }
    std::ranges::copy(shard, out.begin() + static_cast<std::ptrdiff_t>(parityHeaderLength(*total)));
    return {};
}

Result<ParityHeader> decodeParityRecord(std::span<const std::byte> payload, std::uint64_t offset) {
    if (payload.size() < headerBaseLength) {
        return fail(ErrorKind::Truncated, "parity record shorter than its header", offset);
    }
    if (loadLe<std::uint32_t>(payload.data() + versionAt) != parityRecordVersion) {
        return fail(
            ErrorKind::Unsupported,
            "unsupported parity record version",
            offset + versionAt
        );
    }
    ParityHeader header;
    header.groupId = loadLe<std::uint64_t>(payload.data() + groupAt);
    header.generation = loadLe<std::uint64_t>(payload.data() + generationAt);
    header.stripeIndex = loadLe<std::uint64_t>(payload.data() + stripeAt);
    header.shardIndex = loadLe<std::uint32_t>(payload.data() + shardAt);
    header.dataShards = loadLe<std::uint32_t>(payload.data() + dataShardsAt);
    header.parityShards = loadLe<std::uint32_t>(payload.data() + parityShardsAt);
    header.shardBytes = loadLe<std::uint32_t>(payload.data() + shardBytesAt);
    header.stripeCount = loadLe<std::uint64_t>(payload.data() + stripeCountAt);
    header.streamLength = loadLe<std::uint64_t>(payload.data() + streamLengthAt);

    auto total = checkedAdd(header.dataShards, header.parityShards);
    if (header.dataShards == 0 || header.parityShards == 0 || !total || *total > 256) {
        return fail(ErrorKind::Malformed, "parity record has an invalid shard count", offset);
    }
    if (header.shardBytes == 0 || header.shardBytes > bale::parity::maxShardBytes) {
        return fail(
            ErrorKind::LimitExceeded,
            "parity shard size outside the supported range",
            offset + shardBytesAt
        );
    }
    if (header.shardIndex < header.dataShards || header.shardIndex >= *total) {
        return fail(ErrorKind::Malformed, "parity shard index is not a parity shard", offset);
    }
    if (header.stripeCount == 0 || header.stripeIndex >= header.stripeCount) {
        return fail(ErrorKind::Malformed, "parity stripe index outside the stripe count", offset);
    }
    if (header.groupId == 0 || header.generation == 0 || header.streamLength == 0) {
        return fail(ErrorKind::Malformed, "parity record carries an empty identity", offset);
    }
    auto headerLength = parityHeaderLength(*total);
    auto want = checkedAdd(
        static_cast<std::uint64_t>(headerLength),
        static_cast<std::uint64_t>(header.shardBytes)
    );
    if (!want || *want != payload.size()) {
        return fail(ErrorKind::Malformed, "parity record length does not match its layout", offset);
    }
    auto stripeBytes = checkedMul(
        static_cast<std::uint64_t>(header.dataShards),
        static_cast<std::uint64_t>(header.shardBytes)
    );
    if (!stripeBytes) {
        return fail(ErrorKind::LimitExceeded, "parity stripe size overflows", offset);
    }
    auto capacity = checkedMul(header.stripeCount, *stripeBytes);
    if (!capacity || header.streamLength > *capacity ||
        header.streamLength <= *capacity - *stripeBytes) {
        return fail(ErrorKind::Malformed, "parity stream length disagrees with its layout", offset);
    }
    header.crc.resize(*total);
    for (std::uint32_t index = 0; index < *total; ++index) {
        header.crc[index] =
            loadLe<std::uint32_t>(payload.data() + crcTableAt + index * sizeof(std::uint32_t));
    }
    return header;
}

Result<void> checkParityHeader(
    const ParityHeader& header,
    const ParityDescriptor& descriptor,
    std::uint64_t generation,
    std::uint64_t offset
) {
    if (!descriptor.present) {
        return fail(ErrorKind::Malformed, "parity record in a generation without parity", offset);
    }
    if (header.generation != generation || header.groupId != descriptor.groupId ||
        header.dataShards != descriptor.dataShards ||
        header.parityShards != descriptor.parityShards ||
        header.shardBytes != descriptor.shardBytes ||
        header.stripeCount != descriptor.stripeCount) {
        return fail(ErrorKind::Integrity, "parity record disagrees with its footer", offset);
    }
    return {};
}

}
