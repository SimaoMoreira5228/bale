#include "base/endian.hpp"
#include "formats/zip/reader.hpp"

namespace bale::zip {

namespace {

constexpr std::uint32_t centralHeaderSignature = 0x02014b50;
constexpr std::size_t centralHeaderSize = 46;
constexpr std::size_t localHeaderSize = 30;
constexpr std::uint16_t zip64ExtraId = 0x0001;
constexpr std::uint16_t extendedTimestampId = 0x5455;
constexpr std::uint16_t madeByUnix = 3;
constexpr std::uint32_t saturated32 = 0xFFFFFFFF;
constexpr std::uint16_t saturated16 = 0xFFFF;

struct Saturated {
    bool uncompressedSize = false;
    bool compressedSize = false;
    bool localHeaderOffset = false;
    bool diskStart = false;

    [[nodiscard]] bool any() const {
        return uncompressedSize || compressedSize || localHeaderOffset || diskStart;
    }
};

Result<void> readZip64Extra(
    std::span<const std::byte> data,
    std::uint64_t offset,
    const Saturated& saturated,
    Entry& entry,
    std::uint32_t& diskStart
) {
    ByteReader reader(data, offset);
    if (saturated.uncompressedSize) {
        auto value = reader.u64le();
        if (!value) {
            return fail(ErrorKind::Malformed, "ZIP64 extra field too short", offset);
        }
        entry.uncompressedSize = *value;
    }
    if (saturated.compressedSize) {
        auto value = reader.u64le();
        if (!value) {
            return fail(ErrorKind::Malformed, "ZIP64 extra field too short", offset);
        }
        entry.compressedSize = *value;
    }
    if (saturated.localHeaderOffset) {
        auto value = reader.u64le();
        if (!value) {
            return fail(ErrorKind::Malformed, "ZIP64 extra field too short", offset);
        }
        entry.localHeaderOffset = *value;
    }
    if (saturated.diskStart) {
        auto value = reader.u32le();
        if (!value) {
            return fail(ErrorKind::Malformed, "ZIP64 extra field too short", offset);
        }
        diskStart = *value;
    }
    return {};
}

Result<void>
readTimestampExtra(std::span<const std::byte> data, std::uint64_t offset, Entry& entry) {
    if (data.empty()) {
        return fail(ErrorKind::Malformed, "empty extended timestamp extra field", offset);
    }

    auto present = std::to_integer<std::uint8_t>(data[0]);
    if ((present & 0x01) == 0) {
        return {};
    }
    if (data.size() < 5) {
        return fail(ErrorKind::Malformed, "extended timestamp extra field too short", offset);
    }

    auto raw = loadLe<std::uint32_t>(data.data() + 1);
    entry.modifiedUnixTime = static_cast<std::int32_t>(raw);
    return {};
}

Result<void> readExtraFields(
    std::span<const std::byte> extra,
    std::uint64_t offset,
    const Saturated& saturated,
    Entry& entry,
    std::uint32_t& diskStart
) {
    bool sawZip64 = false;
    bool sawTimestamp = false;
    ByteReader reader(extra, offset);
    while (!reader.empty()) {
        auto fieldOffset = reader.offset();
        if (reader.remaining() < 4) {
            return fail(ErrorKind::Malformed, "truncated extra field header", fieldOffset);
        }

        auto id = reader.u16le();
        auto size = reader.u16le();
        auto body = reader.bytes(*size);
        if (!body) {
            return fail(ErrorKind::Malformed, "extra field overruns its area", fieldOffset);
        }

        if (*id == zip64ExtraId) {
            if (sawZip64) {
                return fail(ErrorKind::Malformed, "duplicate ZIP64 extra field", fieldOffset);
            }
            sawZip64 = true;

            auto parsed = readZip64Extra(*body, fieldOffset + 4, saturated, entry, diskStart);
            if (!parsed) {
                return parsed;
            }
        } else if (*id == extendedTimestampId) {
            if (sawTimestamp) {
                return fail(ErrorKind::Malformed, "duplicate extended timestamp", fieldOffset);
            }
            sawTimestamp = true;

            auto parsed = readTimestampExtra(*body, fieldOffset + 4, entry);
            if (!parsed) {
                return parsed;
            }
        }
    }

    if (saturated.any() && !sawZip64) {
        return fail(ErrorKind::Malformed, "saturated field without ZIP64 extra", offset);
    }
    return {};
}

std::string_view asText(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

}

DosDateTime decodeDosDateTime(std::uint16_t date, std::uint16_t time) {
    DosDateTime result;
    result.year = static_cast<std::uint16_t>(1980 + (date >> 9));
    result.month = static_cast<std::uint8_t>((date >> 5) & 0x0F);
    result.day = static_cast<std::uint8_t>(date & 0x1F);
    result.hour = static_cast<std::uint8_t>(time >> 11);
    result.minute = static_cast<std::uint8_t>((time >> 5) & 0x3F);
    result.second = static_cast<std::uint8_t>((time & 0x1F) * 2);
    return result;
}

Result<bool> Cursor::next(Entry& entry) {
    if (remaining_ == 0) {
        if (!reader_.empty()) {
            return fail(
                ErrorKind::Malformed,
                "central directory has more data than its entry count",
                reader_.offset()
            );
        }
        return false;
    }

    auto headerOffset = reader_.offset();
    if (reader_.empty()) {
        return fail(
            ErrorKind::Malformed,
            "central directory has fewer entries than its entry count",
            headerOffset
        );
    }

    auto fixed = reader_.bytes(centralHeaderSize);
    if (!fixed) {
        return fail(ErrorKind::Malformed, "truncated central directory header", headerOffset);
    }

    const std::byte* header = fixed->data();
    if (loadLe<std::uint32_t>(header) != centralHeaderSignature) {
        return fail(ErrorKind::Malformed, "bad central directory header signature", headerOffset);
    }

    entry = Entry{};
    entry.versionMadeBy = loadLe<std::uint16_t>(header + 4);
    entry.versionNeeded = loadLe<std::uint16_t>(header + 6);
    entry.flags = loadLe<std::uint16_t>(header + 8);
    entry.method = loadLe<std::uint16_t>(header + 10);
    entry.dosTime = loadLe<std::uint16_t>(header + 12);
    entry.dosDate = loadLe<std::uint16_t>(header + 14);
    entry.crc32 = loadLe<std::uint32_t>(header + 16);
    entry.compressedSize = loadLe<std::uint32_t>(header + 20);
    entry.uncompressedSize = loadLe<std::uint32_t>(header + 24);
    entry.internalAttributes = loadLe<std::uint16_t>(header + 36);
    entry.externalAttributes = loadLe<std::uint32_t>(header + 38);
    entry.localHeaderOffset = loadLe<std::uint32_t>(header + 42);

    auto nameLength = loadLe<std::uint16_t>(header + 28);
    auto extraLength = loadLe<std::uint16_t>(header + 30);
    auto commentLength = loadLe<std::uint16_t>(header + 32);
    std::uint32_t diskStart = loadLe<std::uint16_t>(header + 34);

    if (nameLength > maxNameLength_) {
        return fail(ErrorKind::LimitExceeded, "entry name exceeds limit", headerOffset);
    }

    auto variableLength = std::size_t{nameLength} + extraLength + commentLength;
    if (variableLength > reader_.remaining()) {
        return fail(
            ErrorKind::Malformed,
            "central directory header overruns central directory",
            headerOffset
        );
    }

    auto name = reader_.bytes(nameLength);
    auto extraOffset = reader_.offset();
    auto extra = reader_.bytes(extraLength);
    auto comment = reader_.bytes(commentLength);
    entry.name = asText(*name);
    entry.extra = *extra;
    entry.comment = asText(*comment);

    Saturated saturated;
    saturated.uncompressedSize = entry.uncompressedSize == saturated32;
    saturated.compressedSize = entry.compressedSize == saturated32;
    saturated.localHeaderOffset = entry.localHeaderOffset == saturated32;
    saturated.diskStart = diskStart == saturated16;

    auto extras = readExtraFields(*extra, extraOffset, saturated, entry, diskStart);
    if (!extras) {
        return std::unexpected(extras.error());
    }

    if (diskStart != 0) {
        return fail(ErrorKind::Unsupported, "entry starts on another disk", headerOffset);
    }
    if (entry.localHeaderOffset > directoryOffset_ ||
        directoryOffset_ - entry.localHeaderOffset < localHeaderSize) {
        return fail(
            ErrorKind::Malformed,
            "local header offset outside the data area",
            headerOffset
        );
    }
    if ((entry.versionMadeBy >> 8) == madeByUnix) {
        entry.unixMode = static_cast<std::uint16_t>(entry.externalAttributes >> 16);
    }

    --remaining_;
    return true;
}

}
