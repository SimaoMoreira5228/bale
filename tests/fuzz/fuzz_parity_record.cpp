#include "archive/parity.hpp"

#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "fuzz/memory_file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

void require(bool condition) {
    if (!condition) {
        __builtin_trap();
    }
}

void checkRecord(std::span<const std::byte> input) {
    auto decoded = bale::archive::decodeParityRecord(input, 0);
    if (!decoded) {
        return;
    }
    require(decoded->dataShards >= 1);
    require(decoded->parityShards >= 1);
    require(decoded->dataShards + decoded->parityShards <= 256);
    require(decoded->shardBytes >= 1);
    require(decoded->stripeCount >= 1);
    require(decoded->shardIndex >= decoded->dataShards);
    require(decoded->shardIndex < decoded->dataShards + decoded->parityShards);
    require(decoded->crc.size() == decoded->dataShards + decoded->parityShards);

    std::vector<std::byte> shard(decoded->shardBytes, std::byte{0xA5});
    std::vector<std::byte> encoded;
    require(bale::archive::encodeParityRecord(*decoded, shard, encoded).has_value());
    auto again = bale::archive::decodeParityRecord(encoded, 0);
    require(again.has_value());
    require(again->groupId == decoded->groupId);
    require(again->generation == decoded->generation);
    require(again->stripeIndex == decoded->stripeIndex);
    require(again->shardIndex == decoded->shardIndex);
    require(again->streamLength == decoded->streamLength);
    require(again->crc == decoded->crc);

    bale::ParityDescriptor descriptor;
    descriptor.present = true;
    descriptor.dataShards = decoded->dataShards;
    descriptor.parityShards = decoded->parityShards;
    descriptor.shardBytes = decoded->shardBytes;
    descriptor.stripeCount = decoded->stripeCount;
    descriptor.groupId = decoded->groupId;
    auto checked = bale::archive::checkParityHeader(*decoded, descriptor, decoded->generation, 0);
    require(checked.has_value());

    bale::ParityDescriptor foreign = descriptor;
    foreign.groupId ^= 1;
    require(!bale::archive::checkParityHeader(*decoded, foreign, decoded->generation, 0));
    bale::ParityDescriptor absent;
    require(!bale::archive::checkParityHeader(*decoded, absent, decoded->generation, 0));
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    checkRecord(input);
    if (input.size() >= 60) {
        std::vector<std::byte> fixed(input.begin(), input.end());
        bale::storeLe(fixed.data(), bale::archive::parityRecordVersion);
        std::uint32_t total = 2;
        bale::storeLe(fixed.data() + 32, std::uint32_t{1});
        bale::storeLe(fixed.data() + 36, std::uint32_t{1});
        bale::storeLe(fixed.data() + 40, std::uint32_t{8});
        bale::storeLe(fixed.data() + 44, std::uint64_t{1});
        bale::storeLe(fixed.data() + 52, std::uint64_t{8});
        bale::storeLe(fixed.data() + 28, std::uint32_t{1});
        std::uint64_t headerLength = bale::archive::parityHeaderLength(total);
        fixed.resize(static_cast<std::size_t>(headerLength + 8));
        for (std::uint32_t index = 0; index < total; ++index) {
            bale::storeLe(
                fixed.data() + 60 + index * 4,
                bale::Crc32c::of(
                    std::span(fixed).subspan(static_cast<std::size_t>(headerLength), 8)
                )
            );
        }
        checkRecord(fixed);
    }
    return 0;
}
