#pragma once

#include "archive/chunk.hpp"
#include "archive/writer_profile.hpp"
#include "base/error.hpp"
#include "security/budget.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::archive {

inline constexpr std::uint64_t manifestSchemaVersion = 1;

enum class EntryKind : std::uint8_t {
    Regular = 1,
    Directory = 2,
    Symlink = 3,
    HardLink = 4,
};

inline constexpr std::uint32_t maxPermissionBits = 07777;

struct ManifestEntry {
    std::string_view path{};
    std::string_view target{};
    std::uint64_t length = 0;
    std::optional<std::int64_t> mtimeNanoseconds{};
    std::optional<std::uint32_t> mode{};
    std::uint32_t firstChunk = 0;
    std::uint32_t chunkCount = 0;
    EntryKind kind = EntryKind::Regular;
};

struct Manifest {
    std::vector<ManifestEntry> entries;
    std::vector<ChunkKey> chunks;
    std::string_view comment;
    WriterMetadata writer;

    [[nodiscard]] std::span<const ChunkKey> chunksOf(const ManifestEntry& entry) const {
        return std::span(chunks).subspan(entry.firstChunk, entry.chunkCount);
    }
};

[[nodiscard]] Result<void> encodeManifest(const Manifest& manifest, std::vector<std::byte>& out);

[[nodiscard]] Result<void> decodeManifest(
    std::span<const std::byte> payload,
    std::uint64_t offset,
    const Limits& limits,
    Manifest& out
);

[[nodiscard]] Result<void>
validateEntryPath(std::string_view path, const Limits& limits, std::string& scratch);

[[nodiscard]] const ManifestEntry*
findEntry(std::span<const ManifestEntry> entries, std::string_view path);

}
