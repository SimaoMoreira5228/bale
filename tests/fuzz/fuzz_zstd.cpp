#include "formats/zstd/stream.hpp"
#include "fuzz/memory_file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    static_cast<void>(bale::zstd::looksLikeZstd(input));

    auto file = bale::fuzz::memoryFile(input);
    if (!file) {
        return 0;
    }

    bale::zstd::Limits limits;
    limits.maxOutputBytes = std::uint64_t{1} << 22;
    limits.chunkBytes = 4096;
    auto stream = bale::zstd::Stream::open(std::move(*file), limits);
    if (!stream) {
        return 0;
    }

    std::array<std::byte, 4096> out{};
    while (true) {
        auto count = stream->read(out);
        if (!count || *count == 0) {
            break;
        }
        if (stream->outputBytes() > limits.maxOutputBytes) {
            __builtin_trap();
        }
    }
    return 0;
}
