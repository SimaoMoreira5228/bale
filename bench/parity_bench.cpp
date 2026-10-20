#include "parity/reed_solomon.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <span>
#include <vector>

using namespace bale;
using namespace bale::parity;

namespace {

constexpr int runs = 5;

struct Timings {
    double encode = 0;
    double repair = 0;
};

Timings measure(std::uint32_t dataShards, std::uint32_t parityShards, std::size_t shardBytes) {
    auto coder = ReedSolomon::make(dataShards, parityShards).value();
    const std::uint32_t total = dataShards + parityShards;

    std::mt19937_64 random(0x243F6A8885A308D3);
    std::vector<std::vector<std::byte>> store(total, std::vector<std::byte>(shardBytes));
    for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
        for (std::size_t index = 0; index < shardBytes; ++index) {
            store[shard][index] = static_cast<std::byte>(random());
        }
    }
    std::vector<std::span<const std::byte>> dataSpans(dataShards);
    std::vector<std::span<std::byte>> paritySpans(parityShards);
    std::vector<std::span<std::byte>> allSpans(total);
    for (std::uint32_t shard = 0; shard < total; ++shard) {
        allSpans[shard] = store[shard];
        if (shard < dataShards) {
            dataSpans[shard] = store[shard];
        } else {
            paritySpans[shard - dataShards] = store[shard];
        }
    }

    auto encodeOnce = [&] {
        if (auto encoded = coder.encode(dataSpans, paritySpans); !encoded) {
            std::printf("encode failed\n");
        }
    };
    encodeOnce();

    std::vector<std::uint32_t> missing(parityShards);
    for (std::uint32_t shard = 0; shard < parityShards; ++shard) {
        missing[shard] = shard;
    }
    std::vector<std::byte> scratch(*ReedSolomon::scratchBytes(dataShards, parityShards));

    Timings best;
    for (int run = 0; run < runs; ++run) {
        auto start = std::chrono::steady_clock::now();
        encodeOnce();
        std::chrono::duration<double> encodeElapsed = std::chrono::steady_clock::now() - start;
        const double dataBytes = static_cast<double>(dataShards * shardBytes);
        if (best.encode == 0 || dataBytes / encodeElapsed.count() > best.encode) {
            best.encode = dataBytes / encodeElapsed.count() / 1e9;
        }

        start = std::chrono::steady_clock::now();
        if (auto repaired = coder.repair(allSpans, missing, scratch); !repaired) {
            std::printf("repair failed\n");
        }
        std::chrono::duration<double> repairElapsed = std::chrono::steady_clock::now() - start;
        if (best.repair == 0 || dataBytes / repairElapsed.count() > best.repair) {
            best.repair = dataBytes / repairElapsed.count() / 1e9;
        }
    }
    return best;
}

}

int main() {
    std::printf("%-9s %9s %8s %12s %12s\n", "shards", "kB/shard", "op", "GB/s(data)", "note");
    for (auto [dataShards, parityShards] : {
             std::pair<std::uint32_t, std::uint32_t>{4, 2},
             {10, 4},
             {17, 3},
         }) {
        for (std::size_t shardBytes : {std::size_t{64} << 10, std::size_t{1} << 20}) {
            Timings timings = measure(dataShards, parityShards, shardBytes);
            std::printf(
                "%3u+%u      %7zu %-8s %12.2f\n",
                dataShards,
                parityShards,
                shardBytes >> 10,
                "encode",
                timings.encode
            );
            std::printf(
                "%3u+%u      %7zu %-8s %12.2f   worst case: first k present\n",
                dataShards,
                parityShards,
                shardBytes >> 10,
                "repair",
                timings.repair
            );
        }
    }
    return 0;
}
