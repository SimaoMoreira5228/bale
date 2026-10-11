#pragma once

#include "base/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace bale {

enum class RecordType : std::uint8_t {
    Data = 1,
    Manifest = 2,
    Index = 3,
    Commit = 4,
    Extension = 5,
};

// NOTE: matches the wire width so unregistered codec IDs survive framing for later rejection.
// NOLINTNEXTLINE(performance-enum-size)
enum class CodecId : std::uint32_t {
    Raw = 0,
    Zstd = 1,
};

[[nodiscard]] constexpr std::string_view codecName(CodecId codec) {
    switch (codec) {
    case CodecId::Raw:
        return "raw";
    case CodecId::Zstd:
        return "zstd";
    }
    return "unknown";
}

inline constexpr std::size_t recordPrefixSize = 48;
inline constexpr std::size_t recordTrailerSize = 8;
inline constexpr std::uint64_t recordFramingSize = recordPrefixSize + recordTrailerSize;

inline constexpr std::uint16_t requiredRecordFlagMask = 0x00FF;
inline constexpr std::uint16_t knownRequiredRecordFlags = 0;

inline constexpr std::array recordMagic{
    std::byte{0x42},
    std::byte{0x4C},
    std::byte{0x52},
    std::byte{0x31},
};

inline constexpr std::array recordEndMarker{
    std::byte{0x45},
    std::byte{0x4E},
    std::byte{0x44},
    std::byte{0x31},
};

struct RecordHeader {
    RecordType type = RecordType::Data;
    std::uint16_t flags = 0;
    std::uint64_t payloadLength = 0;
    std::uint64_t decodedLength = 0;
    std::uint64_t sequence = 0;
    CodecId codec = CodecId::Raw;
};

struct RecordLimits {
    std::uint64_t maxPayloadLength = 0;
    std::uint64_t maxDecodedLength = 0;
};

struct Record {
    RecordHeader header;
    std::span<const std::byte> payload;
    std::uint64_t size = 0;
};

[[nodiscard]] Result<std::uint64_t> recordSize(std::uint64_t payloadLength);

[[nodiscard]] std::array<std::byte, recordPrefixSize>
encodeRecordPrefix(const RecordHeader& header);

[[nodiscard]] std::array<std::byte, recordTrailerSize>
encodeRecordTrailer(std::uint32_t payloadChecksum);

[[nodiscard]] Result<RecordHeader> decodeRecordPrefix(
    std::span<const std::byte> data,
    const RecordLimits& limits,
    std::uint64_t offset = 0
);

[[nodiscard]] Result<void> verifyRecordTrailer(
    std::span<const std::byte> payload,
    std::span<const std::byte> trailer,
    std::uint64_t trailerOffset = 0
);

[[nodiscard]] Result<Record>
decodeRecord(std::span<const std::byte> data, const RecordLimits& limits, std::uint64_t offset = 0);

}
