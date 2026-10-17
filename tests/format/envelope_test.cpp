#include "checksum/crc.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

using namespace bale;

namespace {

constexpr std::uint64_t maxU64 = std::numeric_limits<std::uint64_t>::max();

constexpr RecordLimits generousLimits{
    .maxPayloadLength = 1 << 20,
    .maxDecodedLength = 1 << 20,
};

std::vector<std::byte> fromHex(std::string_view hex) {
    std::vector<std::byte> out;
    auto nibble = [](char digit) {
        return digit <= '9' ? digit - '0' : digit - 'A' + 10;
    };
    for (std::size_t index = 0; index + 1 < hex.size(); index += 3) {
        out.push_back(static_cast<std::byte>(nibble(hex[index]) * 16 + nibble(hex[index + 1])));
    }
    return out;
}

std::uint32_t bitwiseCrc32c(std::span<const std::byte> data) {
    std::uint32_t crc = 0xFFFFFFFF;
    for (std::byte value : data) {
        crc ^= std::to_integer<std::uint32_t>(value);
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1) != 0 ? (crc >> 1) ^ 0x82F63B78 : crc >> 1;
        }
    }
    return ~crc;
}

std::uint32_t storedU32(std::span<const std::byte> bytes, std::size_t at) {
    std::uint32_t value = 0;
    for (std::size_t index = 0; index < 4; ++index) {
        value |= std::to_integer<std::uint32_t>(bytes[at + index]) << (8 * index);
    }
    return value;
}

std::uint32_t bitwiseCrcWithFieldZeroed(std::span<const std::byte> original, std::size_t at) {
    std::vector bytes(original.begin(), original.end());
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[at + index] = std::byte{0};
    }
    return bitwiseCrc32c(bytes);
}

std::vector<std::byte> assembleRecord(RecordHeader header, std::span<const std::byte> payload) {
    header.payloadLength = payload.size();
    auto prefix = encodeRecordPrefix(header);
    auto trailer = encodeRecordTrailer(Crc32c::of(payload));

    std::vector<std::byte> out(prefix.begin(), prefix.end());
    out.insert(out.end(), payload.begin(), payload.end());
    out.insert(out.end(), trailer.begin(), trailer.end());
    return out;
}

std::array<std::byte, recordPrefixSize>
prefixWith(std::uint64_t payloadLength, std::uint64_t decodedLength) {
    RecordHeader header;
    header.payloadLength = payloadLength;
    header.decodedLength = decodedLength;
    header.codec = CodecId::Zstd;
    return encodeRecordPrefix(header);
}

std::vector<std::byte> goldenSuperblock() {
    return fromHex(
        "42 41 4C 45 0D 0A 1A 0A 01 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 "
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 15 CD 85 3D FE 9C 97 17 "
        "00 00 00 00 00 00 00 00 65 B0 EA DE 00 00 00 00"
    );
}

std::vector<std::byte> goldenEmptyDataRecord() {
    return fromHex(
        "42 4C 52 31 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "01 00 00 00 00 00 00 00 00 00 00 00 25 BF 2D B9 00 00 00 00 00 00 00 00 "
        "00 00 00 00 45 4E 44 31"
    );
}

std::vector<std::byte> goldenManifestRecord() {
    return fromHex(
        "42 4C 52 31 02 00 00 00 04 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 "
        "07 00 00 00 00 00 00 00 00 00 00 00 C0 4B E5 05 00 00 00 00 00 00 00 00 "
        "62 61 6C 65 85 CA D6 0F 45 4E 44 31"
    );
}

std::vector<std::byte> goldenFooter() {
    return fromHex(
        "42 41 4C 45 46 54 52 31 40 00 00 00 00 00 00 00 3C 00 00 00 00 00 00 00 "
        "03 00 00 00 00 00 00 00 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F "
        "30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F AA 1A C8 5E 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    );
}

Superblock sampleSuperblock() {
    Superblock superblock;
    for (std::size_t index = 0; index < superblock.archiveId.size(); ++index) {
        superblock.archiveId[index] = static_cast<std::byte>(index);
    }
    superblock.creationTimeNs = 1700000000123456789;
    return superblock;
}

Footer sampleFooter() {
    Footer footer;
    footer.commitOffset = 64;
    footer.commitLength = 60;
    footer.generation = 3;
    for (std::size_t index = 0; index < footer.commitDigest.size(); ++index) {
        footer.commitDigest[index] = static_cast<std::byte>(0x20 + index);
    }
    return footer;
}

}

TEST_CASE("golden vectors carry CRC32C values confirmed by an independent bitwise implementation") {
    auto superblock = goldenSuperblock();
    auto emptyData = goldenEmptyDataRecord();
    auto manifest = goldenManifestRecord();
    auto footer = goldenFooter();

    CHECK(storedU32(superblock, 56) == bitwiseCrc32c(std::span(superblock).first(56)));
    CHECK(
        storedU32(emptyData, 36) == bitwiseCrcWithFieldZeroed(std::span(emptyData).first(48), 36)
    );
    CHECK(storedU32(emptyData, 48) == bitwiseCrc32c({}));
    CHECK(storedU32(manifest, 36) == bitwiseCrcWithFieldZeroed(std::span(manifest).first(48), 36));
    CHECK(storedU32(manifest, 52) == bitwiseCrc32c(std::span(manifest).subspan(48, 4)));
    CHECK(storedU32(footer, 64) == bitwiseCrcWithFieldZeroed(footer, 64));
}

TEST_CASE("superblock encodes to the golden bytes and decodes back") {
    auto encoded = encodeSuperblock(sampleSuperblock());
    CHECK(std::vector(encoded.begin(), encoded.end()) == goldenSuperblock());

    auto decoded = decodeSuperblock(goldenSuperblock());
    REQUIRE(decoded);
    CHECK(decoded->minor == 0);
    CHECK(decoded->requiredFeatures == 0);
    CHECK(decoded->optionalFeatures == 0);
    CHECK(decoded->archiveId == sampleSuperblock().archiveId);
    CHECK(decoded->creationTimeNs == 1700000000123456789);
}

TEST_CASE("superblock round-trips negative times, a newer minor and unknown optional features") {
    Superblock superblock = sampleSuperblock();
    superblock.minor = 7;
    superblock.optionalFeatures = 0xFFFFFFFF;
    superblock.creationTimeNs = std::numeric_limits<std::int64_t>::min();

    auto decoded = decodeSuperblock(encodeSuperblock(superblock));
    REQUIRE(decoded);
    CHECK(decoded->minor == 7);
    CHECK(decoded->optionalFeatures == 0xFFFFFFFF);
    CHECK(decoded->creationTimeNs == std::numeric_limits<std::int64_t>::min());
}

TEST_CASE("every single-byte corruption of the superblock is detected") {
    for (std::size_t at = 0; at < superblockSize; ++at) {
        for (int flip : {0x01, 0x80, 0xFF}) {
            auto corrupt = goldenSuperblock();
            corrupt[at] ^= static_cast<std::byte>(flip);
            CAPTURE(at);
            CAPTURE(flip);
            CHECK_FALSE(decodeSuperblock(corrupt));
        }
    }
}

TEST_CASE(
    "superblock rejects truncation, foreign majors, unknown required features and reserved bits"
) {
    auto golden = goldenSuperblock();
    auto truncated = decodeSuperblock(std::span(golden).first(63));
    REQUIRE_FALSE(truncated);
    CHECK(truncated.error().kind == ErrorKind::Truncated);

    auto major = goldenSuperblock();
    major[8] = std::byte{2};
    CHECK(decodeSuperblock(major).error().kind == ErrorKind::Unsupported);

    Superblock superblock = sampleSuperblock();
    superblock.requiredFeatures = 0x80000000;
    auto required = decodeSuperblock(encodeSuperblock(superblock));
    REQUIRE_FALSE(required);
    CHECK(required.error().kind == ErrorKind::Unsupported);
    CHECK(required.error().offset == 16);

    auto reserved = goldenSuperblock();
    reserved[50] = std::byte{1};
    std::span<const std::byte> covered = std::span(reserved).first(56);
    auto checksum = bitwiseCrc32c(covered);
    for (std::size_t index = 0; index < 4; ++index) {
        reserved[56 + index] = static_cast<std::byte>(checksum >> (8 * index));
    }
    CHECK(decodeSuperblock(reserved).error().kind == ErrorKind::Malformed);
}

TEST_CASE("record prefix and trailer encode to the golden empty DATA and MANIFEST records") {
    RecordHeader data;
    data.sequence = 1;
    CHECK(assembleRecord(data, {}) == goldenEmptyDataRecord());

    RecordHeader manifest;
    manifest.type = RecordType::Manifest;
    manifest.decodedLength = 4;
    manifest.sequence = 7;
    std::string_view payload = "bale";
    CHECK(assembleRecord(manifest, std::as_bytes(std::span(payload))) == goldenManifestRecord());
}

TEST_CASE("decodeRecord validates a whole record and reports its total size") {
    auto withNext = goldenManifestRecord();
    auto emptyData = goldenEmptyDataRecord();
    withNext.insert(withNext.end(), emptyData.begin(), emptyData.end());

    auto record = decodeRecord(withNext, generousLimits, 500);
    REQUIRE(record);
    CHECK(record->header.type == RecordType::Manifest);
    CHECK(record->header.payloadLength == 4);
    CHECK(record->header.decodedLength == 4);
    CHECK(record->header.sequence == 7);
    CHECK(record->header.codec == CodecId::Raw);
    CHECK(record->size == 60);
    CHECK(record->payload.data() == withNext.data() + 48);
    CHECK(record->payload.size() == 4);

    auto next = decodeRecord(std::span(withNext).subspan(60), generousLimits, 560);
    REQUIRE(next);
    CHECK(next->header.type == RecordType::Data);
    CHECK(next->size == 56);
}

TEST_CASE("record framing truncated at every boundary is reported as truncated") {
    auto manifest = goldenManifestRecord();
    for (std::size_t length = 0; length < manifest.size(); ++length) {
        CAPTURE(length);
        auto record = decodeRecord(std::span(manifest).first(length), generousLimits, 1000);
        REQUIRE_FALSE(record);
        CHECK(record.error().kind == ErrorKind::Truncated);
        CHECK(record.error().offset == 1000 + length);
    }

    auto prefixOnly = decodeRecordPrefix(std::span(manifest).first(48), generousLimits);
    REQUIRE(prefixOnly);
    CHECK(prefixOnly->payloadLength == 4);
}

TEST_CASE("every single-byte corruption of a record is detected") {
    for (std::size_t at = 0; at < goldenManifestRecord().size(); ++at) {
        auto corrupt = goldenManifestRecord();
        corrupt[at] ^= std::byte{0x01};
        CAPTURE(at);
        CHECK_FALSE(decodeRecord(corrupt, generousLimits));
    }
}

TEST_CASE(
    "record prefix rejects unknown types, unknown required flags and nonzero reserved bytes"
) {
    RecordHeader header;
    header.type = static_cast<RecordType>(6);
    CHECK(
        decodeRecordPrefix(encodeRecordPrefix(header), generousLimits).error().kind ==
        ErrorKind::Unsupported
    );

    header.type = static_cast<RecordType>(0);
    CHECK(
        decodeRecordPrefix(encodeRecordPrefix(header), generousLimits).error().kind ==
        ErrorKind::Unsupported
    );

    header.type = RecordType::Extension;
    for (int bit = 0; bit < 8; ++bit) {
        header.flags = static_cast<std::uint16_t>(1 << bit);
        auto rejected = decodeRecordPrefix(encodeRecordPrefix(header), generousLimits);
        REQUIRE_FALSE(rejected);
        CHECK(rejected.error().kind == ErrorKind::Unsupported);
    }

    header.flags = 0xFF00;
    auto optional = decodeRecordPrefix(encodeRecordPrefix(header), generousLimits);
    REQUIRE(optional);
    CHECK(optional->type == RecordType::Extension);
    CHECK(optional->flags == 0xFF00);

    auto prefix = encodeRecordPrefix(RecordHeader{});
    prefix[47] = std::byte{1};
    auto checksum = bitwiseCrcWithFieldZeroed(prefix, 36);
    for (std::size_t index = 0; index < 4; ++index) {
        prefix[36 + index] = static_cast<std::byte>(checksum >> (8 * index));
    }
    CHECK(decodeRecordPrefix(prefix, generousLimits).error().kind == ErrorKind::Malformed);
}

TEST_CASE("record lengths are bounded by caller limits and checked against 64-bit overflow") {
    CHECK(recordSize(0) == 56);
    CHECK(recordSize(maxU64 - 56) == maxU64);
    CHECK(recordSize(maxU64 - 55).error().kind == ErrorKind::LimitExceeded);

    auto overLimit = decodeRecordPrefix(
        prefixWith(1025, 1),
        {.maxPayloadLength = 1024, .maxDecodedLength = maxU64}
    );
    REQUIRE_FALSE(overLimit);
    CHECK(overLimit.error().kind == ErrorKind::LimitExceeded);
    CHECK(overLimit.error().offset == 8);

    CHECK(decodeRecordPrefix(
        prefixWith(1024, 1),
        {.maxPayloadLength = 1024, .maxDecodedLength = maxU64}
    ));

    auto decodedOverLimit = decodeRecordPrefix(
        prefixWith(1, 4097),
        {.maxPayloadLength = maxU64, .maxDecodedLength = 4096}
    );
    REQUIRE_FALSE(decodedOverLimit);
    CHECK(decodedOverLimit.error().kind == ErrorKind::LimitExceeded);
    CHECK(decodedOverLimit.error().offset == 16);

    const RecordLimits unbounded{.maxPayloadLength = maxU64, .maxDecodedLength = maxU64};
    CHECK(
        decodeRecordPrefix(prefixWith(maxU64 - 55, 0), unbounded).error().kind ==
        ErrorKind::LimitExceeded
    );
    CHECK(
        decodeRecordPrefix(prefixWith(maxU64, 0), unbounded).error().kind ==
        ErrorKind::LimitExceeded
    );

    auto hugeButValid = decodeRecordPrefix(prefixWith(maxU64 - 56, 0), unbounded);
    REQUIRE(hugeButValid);
    auto hugeRecord = decodeRecord(prefixWith(maxU64 - 56, 0), unbounded);
    REQUIRE_FALSE(hugeRecord);
    CHECK(hugeRecord.error().kind == ErrorKind::Truncated);
}

TEST_CASE("raw records must declare a decoded length equal to the stored length") {
    RecordHeader header;
    header.payloadLength = 4;
    header.decodedLength = 5;
    auto mismatch = decodeRecordPrefix(encodeRecordPrefix(header), generousLimits);
    REQUIRE_FALSE(mismatch);
    CHECK(mismatch.error().kind == ErrorKind::Malformed);

    header.codec = static_cast<CodecId>(77);
    auto unknownCodec = decodeRecordPrefix(encodeRecordPrefix(header), generousLimits);
    REQUIRE(unknownCodec);
    CHECK(unknownCodec->codec == static_cast<CodecId>(77));
}

TEST_CASE("record trailer distinguishes a missing end marker from a payload checksum mismatch") {
    auto badMarker = goldenManifestRecord();
    badMarker[59] = std::byte{0x32};
    auto marker = decodeRecord(badMarker, generousLimits, 100);
    REQUIRE_FALSE(marker);
    CHECK(marker.error().kind == ErrorKind::Malformed);
    CHECK(marker.error().offset == 156);

    auto badPayload = goldenManifestRecord();
    badPayload[49] = std::byte{0x00};
    auto payload = decodeRecord(badPayload, generousLimits, 100);
    REQUIRE_FALSE(payload);
    CHECK(payload.error().kind == ErrorKind::Integrity);
    CHECK(payload.error().offset == 152);
}

TEST_CASE("footer encodes to the golden bytes and decodes back") {
    auto encoded = encodeFooter(sampleFooter());
    CHECK(std::vector(encoded.begin(), encoded.end()) == goldenFooter());

    auto decoded = decodeFooter(goldenFooter(), 124);
    REQUIRE(decoded);
    CHECK(decoded->commitOffset == 64);
    CHECK(decoded->commitLength == 60);
    CHECK(decoded->generation == 3);
    CHECK(decoded->commitDigest == sampleFooter().commitDigest);
}

TEST_CASE("every single-byte corruption of the footer is detected") {
    for (std::size_t at = 0; at < footerSize; ++at) {
        auto corrupt = goldenFooter();
        corrupt[at] ^= std::byte{0x01};
        CAPTURE(at);
        CHECK_FALSE(decodeFooter(corrupt, 124));
    }
}

TEST_CASE("footer rejects truncation and commit spans outside the archive body") {
    auto golden = goldenFooter();
    CHECK(decodeFooter(std::span(golden).first(95), 124).error().kind == ErrorKind::Truncated);
    CHECK(decodeFooter(golden, 123).error().kind == ErrorKind::Malformed);

    Footer footer = sampleFooter();
    footer.commitLength = 55;
    CHECK(decodeFooter(encodeFooter(footer), 1000).error().kind == ErrorKind::Malformed);

    footer = sampleFooter();
    footer.commitOffset = 63;
    CHECK(decodeFooter(encodeFooter(footer), 1000).error().kind == ErrorKind::Malformed);

    footer = sampleFooter();
    footer.commitOffset = maxU64 - 10;
    CHECK(decodeFooter(encodeFooter(footer), maxU64).error().kind == ErrorKind::Malformed);
}
