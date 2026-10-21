#include "formats/cpio/reader.hpp"
#include "formats/detect.hpp"
#include "fuzz/memory_file.hpp"
#include "security/archive_path.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>

namespace {

constexpr std::uint64_t maxStreamedBytes = std::uint64_t{16} << 20;

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    static_cast<void>(bale::cpio::looksLikeCpio(input));

    auto file = bale::fuzz::memoryFile(input);
    if (!file) {
        return 0;
    }
    static_cast<void>(bale::detectFormat(*file));

    auto archive = bale::fuzz::memoryFile(input);
    if (!archive) {
        return 0;
    }

    bale::cpio::Limits limits;
    limits.maxEntries = 4096;
    limits.maxNameBytes = 4096;
    auto reader = bale::cpio::Reader::open(std::move(*archive), limits);
    if (!reader) {
        return 0;
    }

    std::array<std::byte, 8192> scratch{};
    std::string normalized;
    bale::PathPolicy policy;
    bale::Limits pathLimits;

    std::uint64_t streamed = 0;
    auto sink = [&streamed](std::span<const std::byte> chunk) -> bale::Result<void> {
        streamed += chunk.size();
        if (streamed > maxStreamedBytes) {
            return bale::fail(bale::ErrorKind::LimitExceeded, "fuzz output budget exhausted");
        }
        return {};
    };

    for (const auto& entry : reader->entries()) {
        if (streamed > maxStreamedBytes) {
            break;
        }

        auto raw = std::as_bytes(std::span(entry.name));
        static_cast<void>(bale::normalizeArchivePath(raw, policy, pathLimits, normalized));
        if (!entry.linkTarget.empty()) {
            auto target = std::as_bytes(std::span(entry.linkTarget));
            static_cast<void>(bale::normalizeArchivePath(target, policy, pathLimits, normalized));
        }
        static_cast<void>(reader->streamEntry(entry, scratch, sink));
    }
    return 0;
}
