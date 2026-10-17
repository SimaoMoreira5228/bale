#include "codecs/encoders.hpp"
#include "formats/compressed/stream.hpp"
#include "formats/tar/reader.hpp"
#include "formats/tar/source.hpp"
#include "fuzz/memory_file.hpp"
#include "security/archive_path.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t maxEntries = 4096;

bale::tar::Limits tarLimits() {
    bale::tar::Limits limits;
    limits.maxExtendedHeaderBytes = std::uint64_t{64} << 10;
    limits.maxPathBytes = 4096;
    limits.maxEntries = maxEntries;
    return limits;
}

void readEntries(bale::tar::Source source) {
    bale::tar::Reader reader(std::move(source), tarLimits());
    std::array<std::byte, 4096> scratch{};
    std::string normalized;
    bale::PathPolicy policy;
    bale::Limits limits;
    auto sink = [](std::span<const std::byte>) -> bale::Result<void> {
        return {};
    };

    for (std::size_t count = 0; count <= maxEntries; ++count) {
        auto entry = reader.next();
        if (!entry || *entry == nullptr) {
            return;
        }

        auto path = std::as_bytes(std::span((*entry)->path));
        static_cast<void>(bale::normalizeArchivePath(path, policy, limits, normalized));
        if (!(*entry)->linkTarget.empty()) {
            auto target = std::as_bytes(std::span((*entry)->linkTarget));
            static_cast<void>(bale::normalizeArchivePath(target, policy, limits, normalized));
        }

        if ((count & 1) == 0 && !reader.streamData(scratch, sink)) {
            return;
        }
    }
}

void readSeekable(std::span<const std::byte> input) {
    auto file = bale::fuzz::memoryFile(input);
    if (!file) {
        return;
    }
    auto source = bale::tar::Source::open(std::move(*file));
    if (!source) {
        return;
    }
    readEntries(std::move(*source));
}

void readCompressed(std::span<const std::byte> input) {
    static auto encoder = bale::ZstdEncoder::create(1);
    if (!encoder) {
        return;
    }

    std::vector<std::byte> frame(bale::ZstdEncoder::compressBound(input.size()));
    auto size = encoder->compress(input, frame);
    if (!size) {
        return;
    }
    frame.resize(*size);

    auto file = bale::fuzz::memoryFile(frame);
    if (!file) {
        return;
    }
    bale::DecompressLimits limits{
        .maxOutputBytes = std::uint64_t{1} << 22,
        .chunkBytes = 4096,
    };
    auto stream = bale::CompressedStream::open(std::move(*file), bale::Compression::Zstd, limits);
    if (!stream) {
        return;
    }
    readEntries(bale::tar::Source(std::move(*stream)));
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    readSeekable(input);
    readCompressed(input);
    return 0;
}
