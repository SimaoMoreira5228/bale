#include "checksum/crc.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <random>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

using namespace bale;

namespace {

constexpr std::size_t bytesPerRun = std::size_t{1} << 30;
constexpr int runs = 5;

double gigabytesPerSecond(CrcFunction function, std::span<const std::byte> buffer) {
    const std::size_t iterations = bytesPerRun / buffer.size();
    double best = 0;
    std::uint32_t sink = 0;

    for (int run = 0; run < runs; ++run) {
        auto start = std::chrono::steady_clock::now();
        for (std::size_t i = 0; i < iterations; ++i) {
            sink = function(sink, buffer);
        }
        std::chrono::duration<double> elapsed = std::chrono::steady_clock::now() - start;

        const double bytes = static_cast<double>(iterations * buffer.size());
        best = std::max(best, bytes / elapsed.count() / 1e9);
    }

    if (sink == 0x12345678) {
        std::puts("");
    }
    return best;
}

void report(std::string_view algorithm, const CrcKernel& kernel, std::span<const std::byte> data) {
    for (std::size_t size : {std::size_t{4096}, std::size_t{1} << 20}) {
        std::printf(
            "%-7.*s %-13.*s %8zu bytes  %6.2f GB/s\n",
            static_cast<int>(algorithm.size()),
            algorithm.data(),
            static_cast<int>(kernel.name.size()),
            kernel.name.data(),
            size,
            gigabytesPerSecond(kernel.function, data.first(size))
        );
    }
}

}

int main() {
    std::vector<std::byte> data(std::size_t{1} << 20);
    std::mt19937_64 random(std::random_device{}());
    for (std::byte& byte : data) {
        byte = static_cast<std::byte>(random());
    }

    for (auto [name, algorithm] : {
             std::pair{std::string_view("crc32"), CrcAlgorithm::Crc32},
             std::pair{std::string_view("crc32c"), CrcAlgorithm::Crc32c},
         }) {
        report(name, portableCrcKernel(algorithm), data);
        if (std::optional<CrcKernel> accelerated = acceleratedCrcKernel(algorithm)) {
            report(name, *accelerated, data);
        }
    }
    return 0;
}
