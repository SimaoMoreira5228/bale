#include "formats/wim/reader.hpp"
#include "fuzz/memory_file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace {

constexpr std::uint64_t maxStreamedBytes = std::uint64_t{16} << 20;

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto file = bale::fuzz::memoryFile(bale::fuzz::bytesOf(data, size));
    if (!file) {
        return 0;
    }

    bale::wim::Limits limits;
    limits.maxEntries = 4096;
    auto reader = bale::wim::Reader::open(std::move(*file), limits);
    if (!reader) {
        return 0;
    }

    std::array<std::byte, 8192> scratch{};
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
        if (entry.kind != bale::wim::EntryKind::Regular &&
            entry.kind != bale::wim::EntryKind::AlternateStream) {
            continue;
        }
        static_cast<void>(reader->streamEntry(entry, scratch, sink));
    }
    return 0;
}
