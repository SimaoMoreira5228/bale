#include "format/record.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"

#include <algorithm>

namespace bale {

namespace {

constexpr std::size_t typeAt = 4;
constexpr std::size_t flagsAt = 6;
constexpr std::size_t payloadLengthAt = 8;
constexpr std::size_t decodedLengthAt = 16;
constexpr std::size_t sequenceAt = 24;
constexpr std::size_t codecAt = 32;
constexpr std::size_t headerCrcAt = 36;
constexpr std::size_t reservedAt = 40;

constexpr std::size_t payloadCrcAt = 0;
constexpr std::size_t endMarkerAt = 4;

std::uint32_t prefixChecksum(std::span<const std::byte, recordPrefixSize> prefix) {
    std::array<std::byte, recordPrefixSize> zeroed{};
    std::ranges::copy(prefix, zeroed.begin());
    std::fill_n(zeroed.begin() + headerCrcAt, 4, std::byte{0});
    return Crc32c::of(zeroed);
}

bool isKnownRecordType(std::uint16_t type) {
    return type >= static_cast<std::uint16_t>(RecordType::Data) &&
        type <= static_cast<std::uint16_t>(RecordType::Parity);
}

}

Result<std::uint64_t> recordSize(std::uint64_t payloadLength) {
    auto size = checkedAdd(payloadLength, recordFramingSize);
    if (!size) {
        return fail(ErrorKind::LimitExceeded, "record size overflows 64 bits");
    }
    return *size;
}

std::array<std::byte, recordPrefixSize> encodeRecordPrefix(const RecordHeader& header) {
    std::array<std::byte, recordPrefixSize> out{};
    std::ranges::copy(recordMagic, out.begin());
    storeLe(out.data() + typeAt, static_cast<std::uint16_t>(header.type));
    storeLe(out.data() + flagsAt, header.flags);
    storeLe(out.data() + payloadLengthAt, header.payloadLength);
    storeLe(out.data() + decodedLengthAt, header.decodedLength);
    storeLe(out.data() + sequenceAt, header.sequence);
    storeLe(out.data() + codecAt, static_cast<std::uint32_t>(header.codec));

    storeLe(out.data() + headerCrcAt, prefixChecksum(out));
    return out;
}

std::array<std::byte, recordTrailerSize> encodeRecordTrailer(std::uint32_t payloadChecksum) {
    std::array<std::byte, recordTrailerSize> out{};
    storeLe(out.data() + payloadCrcAt, payloadChecksum);
    std::ranges::copy(recordEndMarker, out.begin() + endMarkerAt);
    return out;
}

Result<RecordHeader> decodeRecordPrefix(
    std::span<const std::byte> data,
    const RecordLimits& limits,
    std::uint64_t offset
) {
    if (data.size() < recordPrefixSize) {
        return fail(ErrorKind::Truncated, "record prefix truncated", offset + data.size());
    }
    auto prefix = data.first<recordPrefixSize>();

    if (!std::ranges::equal(prefix.first<recordMagic.size()>(), recordMagic)) {
        return fail(ErrorKind::Malformed, "bad record magic", offset);
    }

    auto stored = loadLe<std::uint32_t>(prefix.data() + headerCrcAt);
    if (stored != prefixChecksum(prefix)) {
        return fail(ErrorKind::Integrity, "record header checksum mismatch", offset + headerCrcAt);
    }

    if (loadLe<std::uint64_t>(prefix.data() + reservedAt) != 0) {
        return fail(ErrorKind::Malformed, "record reserved bytes not zero", offset + reservedAt);
    }

    auto type = loadLe<std::uint16_t>(prefix.data() + typeAt);
    if (!isKnownRecordType(type)) {
        return fail(ErrorKind::Unsupported, "unknown record type", offset + typeAt);
    }

    auto flags = loadLe<std::uint16_t>(prefix.data() + flagsAt);
    if ((flags & requiredRecordFlagMask & ~knownRequiredRecordFlags) != 0) {
        return fail(ErrorKind::Unsupported, "unknown required record flag", offset + flagsAt);
    }

    RecordHeader header;
    header.type = static_cast<RecordType>(type);
    header.flags = flags;
    header.payloadLength = loadLe<std::uint64_t>(prefix.data() + payloadLengthAt);
    header.decodedLength = loadLe<std::uint64_t>(prefix.data() + decodedLengthAt);
    header.sequence = loadLe<std::uint64_t>(prefix.data() + sequenceAt);
    header.codec = static_cast<CodecId>(loadLe<std::uint32_t>(prefix.data() + codecAt));

    if (header.payloadLength > limits.maxPayloadLength) {
        return fail(
            ErrorKind::LimitExceeded,
            "record payload length exceeds limit",
            offset + payloadLengthAt
        );
    }

    auto size = recordSize(header.payloadLength);
    if (!size) {
        return fail(size.error().kind, size.error().what, offset + payloadLengthAt);
    }

    if (header.decodedLength > limits.maxDecodedLength) {
        return fail(
            ErrorKind::LimitExceeded,
            "record decoded length exceeds limit",
            offset + decodedLengthAt
        );
    }
    if (header.codec == CodecId::Raw && header.decodedLength != header.payloadLength) {
        return fail(
            ErrorKind::Malformed,
            "raw record decoded length differs from stored length",
            offset + decodedLengthAt
        );
    }
    return header;
}

Result<void> verifyRecordTrailer(
    std::span<const std::byte> payload,
    std::span<const std::byte> trailer,
    std::uint64_t trailerOffset
) {
    if (trailer.size() < recordTrailerSize) {
        return fail(
            ErrorKind::Truncated,
            "record trailer truncated",
            trailerOffset + trailer.size()
        );
    }

    if (!std::ranges::equal(
            trailer.subspan(endMarkerAt, recordEndMarker.size()),
            recordEndMarker
        )) {
        return fail(ErrorKind::Malformed, "missing record end marker", trailerOffset + endMarkerAt);
    }
    if (loadLe<std::uint32_t>(trailer.data() + payloadCrcAt) != Crc32c::of(payload)) {
        return fail(ErrorKind::Integrity, "record payload checksum mismatch", trailerOffset);
    }
    return {};
}

Result<Record>
decodeRecord(std::span<const std::byte> data, const RecordLimits& limits, std::uint64_t offset) {
    auto header = decodeRecordPrefix(data, limits, offset);
    if (!header) {
        return std::unexpected(header.error());
    }

    auto size = recordSize(header->payloadLength);
    if (!size) {
        return std::unexpected(size.error());
    }
    if (*size > data.size()) {
        return fail(ErrorKind::Truncated, "record extends past end of data", offset + data.size());
    }

    auto payloadLength = static_cast<std::size_t>(header->payloadLength);
    auto payload = data.subspan(recordPrefixSize, payloadLength);
    auto trailer = data.subspan(recordPrefixSize + payloadLength, recordTrailerSize);
    auto verified =
        verifyRecordTrailer(payload, trailer, offset + recordPrefixSize + payloadLength);
    if (!verified) {
        return std::unexpected(verified.error());
    }

    return Record{
        .header = *header,
        .payload = payload,
        .size = *size,
    };
}

}
