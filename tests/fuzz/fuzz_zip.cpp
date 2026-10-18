#include "formats/zip/reader.hpp"
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
    auto file = bale::fuzz::memoryFile(bale::fuzz::bytesOf(data, size));
    if (!file) {
        return 0;
    }

    bale::zip::Limits limits;
    limits.maxEntries = 4096;
    limits.maxCentralDirectoryBytes = std::uint64_t{1} << 20;
    auto reader = bale::zip::Reader::open(std::move(*file), limits);
    if (!reader) {
        return 0;
    }
    static_cast<void>(reader->comment());

    std::array<std::byte, 8192> scratch{};
    std::string storage;
    std::string normalized;
    bale::PathPolicy policy;
    policy.backslash = bale::Backslash::Separator;
    bale::Limits pathLimits;

    std::uint64_t streamed = 0;
    auto sink = [&streamed](std::span<const std::byte> chunk) -> bale::Result<void> {
        streamed += chunk.size();
        if (streamed > maxStreamedBytes) {
            return bale::fail(bale::ErrorKind::LimitExceeded, "fuzz output budget exhausted");
        }
        return {};
    };

    auto cursor = reader->entries();
    bale::zip::Entry entry;
    while (streamed <= maxStreamedBytes) {
        auto more = cursor.next(entry);
        if (!more || !*more) {
            break;
        }

        static_cast<void>(bale::zip::decodeDosDateTime(entry.dosDate, entry.dosTime));
        auto name = bale::zip::nameAsUtf8(entry, storage);
        if (name) {
            auto raw = std::as_bytes(std::span(*name));
            static_cast<void>(bale::normalizeArchivePath(raw, policy, pathLimits, normalized));
        }
        static_cast<void>(reader->streamEntry(entry, scratch, sink));
    }
    return 0;
}
