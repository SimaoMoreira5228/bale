#pragma once

#include "base/error.hpp"
#include "format/record.hpp"
#include "format/tlv.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace bale::archive {

enum class Preset : std::uint8_t {
    Fast = 1,
    Balanced = 2,
    Small = 3,
    RestoreFast = 4,
    Portable = 5,
};

inline constexpr std::array allPresets{
    Preset::Fast,
    Preset::Balanced,
    Preset::Small,
    Preset::RestoreFast,
    Preset::Portable,
};

struct CompressionProfile {
    std::optional<Preset> preset;
    CodecId codec = CodecId::Zstd;
    std::int32_t level = 3;
};

enum class ChunkPolicy : std::uint8_t {
    Fixed = 1,
};

[[nodiscard]] CompressionProfile profileFor(Preset preset);

[[nodiscard]] std::string_view presetName(Preset preset);

[[nodiscard]] std::optional<Preset> parsePreset(std::string_view name);

struct WriterMetadata {
    std::string_view name;
    std::optional<std::uint64_t> preset;
    std::optional<std::uint64_t> codec;
    std::optional<std::int64_t> level;
    std::optional<std::uint64_t> chunkPolicy;
    std::optional<std::uint64_t> chunkSize;
    std::optional<std::uint64_t> workers;

    [[nodiscard]] bool empty() const;
};

[[nodiscard]] WriterMetadata describeWriter(
    std::string_view name,
    const CompressionProfile& compression,
    std::uint32_t chunkSize,
    std::uint32_t workers
);

[[nodiscard]] Result<void> encodeWriterMetadata(
    const WriterMetadata& metadata,
    std::uint32_t number,
    TlvWriter& writer,
    std::vector<std::byte>& scratch
);

[[nodiscard]] Result<WriterMetadata> decodeWriterMetadata(const TlvField& field);

}
