#include "checksum/crc.hpp"
#include "fuzz/memory_file.hpp"
#include "parity/reed_solomon.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

std::uint64_t mixState = 0x9E3779B97F4A7C15;

std::uint64_t nextRandom() {
    mixState ^= mixState << 13;
    mixState ^= mixState >> 7;
    mixState ^= mixState << 17;
    return mixState;
}

void require(bool condition) {
    if (!condition) {
        __builtin_trap();
    }
}

void checkRepair(std::span<const std::byte> input) {
    if (input.size() < 8) {
        return;
    }
    mixState = 0x9E3779B97F4A7C15 ^ static_cast<std::uint64_t>(input.size());
    for (std::byte cell : input) {
        mixState = mixState * 1099511628211U ^ static_cast<std::uint64_t>(cell);
    }
    std::uint32_t dataShards =
        1 + static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(input[0]) % 8);
    std::uint32_t parityShards =
        1 + static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(input[1]) % 4);
    std::uint32_t total = dataShards + parityShards;
    std::size_t shardBytes =
        8 + static_cast<std::size_t>(std::to_integer<std::uint8_t>(input[2]) % 24);
    std::vector<std::vector<std::byte>> pristine(total, std::vector<std::byte>(shardBytes));
    for (auto& shard : pristine) {
        for (std::byte& cell : shard) {
            cell = static_cast<std::byte>(nextRandom());
        }
    }
    auto coder = bale::parity::ReedSolomon::make(dataShards, parityShards);
    require(coder.has_value());
    std::vector<std::span<const std::byte>> data(dataShards);
    std::vector<std::span<std::byte>> parity(parityShards);
    for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
        data[shard] = pristine[shard];
    }
    for (std::uint32_t shard = 0; shard < parityShards; ++shard) {
        parity[shard] = pristine[dataShards + shard];
    }
    require(coder->encode(data, parity).has_value());

    std::vector<std::uint32_t> missing;
    std::size_t cursor = 3;
    while (cursor < input.size() && missing.size() <= parityShards + 1) {
        std::uint32_t shard =
            static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(input[cursor])) % total;
        bool seen = false;
        for (std::uint32_t taken : missing) {
            if (taken == shard) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            missing.push_back(shard);
        }
        ++cursor;
    }

    auto scratch =
        std::vector<std::byte>(*bale::parity::ReedSolomon::scratchBytes(dataShards, parityShards));
    auto work = pristine;
    for (std::uint32_t shard : missing) {
        for (std::byte& cell : work[shard]) {
            cell = std::byte{0xA5};
        }
    }
    std::vector<std::span<std::byte>> shards(total);
    for (std::uint32_t shard = 0; shard < total; ++shard) {
        shards[shard] = work[shard];
    }
    auto before = work;
    auto repaired = coder->repair(shards, missing, scratch);
    if (missing.size() > parityShards) {
        require(!repaired.has_value());
        require(repaired.error().kind == bale::ErrorKind::Integrity);
        require(work == before);
        return;
    }
    require(repaired.has_value());
    require(work == pristine);
    std::vector<std::span<const std::byte>> constData(dataShards);
    std::vector<std::span<const std::byte>> constParity(parityShards);
    for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
        constData[shard] = work[shard];
    }
    for (std::uint32_t shard = 0; shard < parityShards; ++shard) {
        constParity[shard] = work[dataShards + shard];
    }
    auto verified = coder->verify(constData, constParity);
    require(verified.has_value() && *verified);

    if (missing.empty() && total > 1 && input.size() > 4) {
        work[0][0] = static_cast<std::byte>(work[0][0] ^ std::byte{0xFF});
        for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
            constData[shard] = work[shard];
        }
        auto tampered = coder->verify(constData, constParity);
        require(tampered.has_value() && !*tampered);
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    checkRepair(input);
    return 0;
}
