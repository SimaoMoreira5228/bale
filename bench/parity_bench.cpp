#include "parity/reed_solomon.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
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

Result<Timings>
measure(std::uint32_t dataShards, std::uint32_t parityShards, std::size_t shardBytes) {
    auto coder = ReedSolomon::make(dataShards, parityShards);
    if (!coder) {
        return tl::unexpected<Error>(coder.error());
    }
    const std::uint32_t total = dataShards + parityShards;

    std::vector<std::vector<std::byte>> store(total, std::vector<std::byte>(shardBytes));
    for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
        std::uint64_t state = 0x243F6A8885A308D3ULL ^ shard;
        for (std::size_t index = 0; index < shardBytes; ++index) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            store[shard][index] = static_cast<std::byte>(state);
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

    auto encodeOnce = [&]() -> Result<void> {
        return coder->encode(dataSpans, paritySpans);
    };
    if (auto encoded = encodeOnce(); !encoded) {
        return tl::unexpected<Error>(encoded.error());
    }

    std::vector<std::uint32_t> missing(parityShards);
    for (std::uint32_t shard = 0; shard < parityShards; ++shard) {
        missing[shard] = shard;
    }
    auto scratchSize = ReedSolomon::scratchBytes(dataShards, parityShards);
    if (!scratchSize) {
        return tl::unexpected<Error>(scratchSize.error());
    }
    std::vector<std::byte> scratch(*scratchSize);

    Timings best;
    for (int run = 0; run < runs; ++run) {
        auto start = std::chrono::steady_clock::now();
        if (auto encoded = encodeOnce(); !encoded) {
            return tl::unexpected<Error>(encoded.error());
        }
        std::chrono::duration<double> encodeElapsed = std::chrono::steady_clock::now() - start;
        const double dataBytes = static_cast<double>(dataShards * shardBytes);
        if (best.encode == 0 || dataBytes / encodeElapsed.count() > best.encode) {
            best.encode = dataBytes / encodeElapsed.count() / 1e9;
        }

        start = std::chrono::steady_clock::now();
        if (auto repaired = coder->repair(allSpans, missing, scratch); !repaired) {
            return tl::unexpected<Error>(repaired.error());
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
            auto measured = measure(dataShards, parityShards, shardBytes);
            if (!measured) {
                std::fprintf(
                    stderr,
                    "parity benchmark failed: %.*s\n",
                    static_cast<int>(measured.error().what.size()),
                    measured.error().what.data()
                );
                return 1;
            }
            Timings timings = *measured;
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
