#include "format/envelope.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/record.hpp"

#include <algorithm>
#include <bit>

namespace bale {

namespace {

constexpr std::size_t superblockMajorAt = 8;
constexpr std::size_t superblockMinorAt = 10;
constexpr std::size_t superblockSizeAt = 12;
constexpr std::size_t superblockRequiredAt = 16;
constexpr std::size_t superblockOptionalAt = 20;
constexpr std::size_t superblockIdAt = 24;
constexpr std::size_t superblockTimeAt = 40;
constexpr std::size_t superblockReservedAt = 48;
constexpr std::size_t superblockCrcAt = 56;
constexpr std::size_t superblockTailAt = 60;

constexpr std::size_t footerOffsetAt = 8;
constexpr std::size_t footerLengthAt = 16;
constexpr std::size_t footerGenerationAt = 24;
constexpr std::size_t footerDigestAt = 32;
constexpr std::size_t footerCrcAt = 64;
constexpr std::size_t footerReservedAt = 68;

bool allZero(std::span<const std::byte> bytes) {
    return std::ranges::all_of(bytes, [](std::byte value) {
        return value == std::byte{0};
    });
}

std::uint32_t footerChecksum(std::span<const std::byte, footerSize> footer) {
    std::array<std::byte, footerSize> zeroed{};
    std::ranges::copy(footer, zeroed.begin());
    std::fill_n(zeroed.begin() + footerCrcAt, 4, std::byte{0});
    return Crc32c::of(zeroed);
}

}

std::array<std::byte, superblockSize> encodeSuperblock(const Superblock& superblock) {
    std::array<std::byte, superblockSize> out{};
    std::ranges::copy(superblockMagic, out.begin());
    storeLe(out.data() + superblockMajorAt, formatMajor);
    storeLe(out.data() + superblockMinorAt, superblock.minor);
    storeLe(out.data() + superblockSizeAt, static_cast<std::uint32_t>(superblockSize));
    storeLe(out.data() + superblockRequiredAt, superblock.requiredFeatures);
    storeLe(out.data() + superblockOptionalAt, superblock.optionalFeatures);
    std::ranges::copy(superblock.archiveId, out.begin() + superblockIdAt);
    storeLe(out.data() + superblockTimeAt, std::bit_cast<std::uint64_t>(superblock.creationTimeNs));

    auto checksum = Crc32c::of(std::span(out).first(superblockCrcAt));
    storeLe(out.data() + superblockCrcAt, checksum);
    return out;
}

Result<Superblock> decodeSuperblock(std::span<const std::byte> data) {
    if (data.size() < superblockSize) {
        return fail(ErrorKind::Truncated, "superblock truncated", data.size());
    }
    auto bytes = data.first<superblockSize>();

    if (!std::ranges::equal(bytes.first<superblockMagic.size()>(), superblockMagic)) {
        return fail(ErrorKind::Malformed, "not a bale archive", 0);
    }
    if (loadLe<std::uint16_t>(bytes.data() + superblockMajorAt) != formatMajor) {
        return fail(ErrorKind::Unsupported, "unsupported format major version", superblockMajorAt);
    }
    if (loadLe<std::uint32_t>(bytes.data() + superblockSizeAt) != superblockSize) {
        return fail(ErrorKind::Malformed, "unexpected superblock size", superblockSizeAt);
    }

    auto stored = loadLe<std::uint32_t>(bytes.data() + superblockCrcAt);
    if (stored != Crc32c::of(bytes.first<superblockCrcAt>())) {
        return fail(ErrorKind::Integrity, "superblock checksum mismatch", superblockCrcAt);
    }

    if (!allZero(bytes.subspan<superblockReservedAt, 8>())) {
        return fail(
            ErrorKind::Malformed,
            "superblock reserved bytes not zero",
            superblockReservedAt
        );
    }
    if (!allZero(bytes.subspan<superblockTailAt>())) {
        return fail(ErrorKind::Malformed, "superblock reserved bytes not zero", superblockTailAt);
    }

    Superblock superblock;
    superblock.minor = loadLe<std::uint16_t>(bytes.data() + superblockMinorAt);
    superblock.requiredFeatures = loadLe<std::uint32_t>(bytes.data() + superblockRequiredAt);
    superblock.optionalFeatures = loadLe<std::uint32_t>(bytes.data() + superblockOptionalAt);
    std::ranges::copy(bytes.subspan<superblockIdAt, 16>(), superblock.archiveId.begin());
    superblock.creationTimeNs =
        std::bit_cast<std::int64_t>(loadLe<std::uint64_t>(bytes.data() + superblockTimeAt));

    if ((superblock.requiredFeatures & ~knownRequiredFeatures) != 0) {
        return fail(ErrorKind::Unsupported, "unknown required feature", superblockRequiredAt);
    }
    return superblock;
}

std::array<std::byte, footerSize> encodeFooter(const Footer& footer) {
    std::array<std::byte, footerSize> out{};
    std::ranges::copy(footerMagic, out.begin());
    storeLe(out.data() + footerOffsetAt, footer.commitOffset);
    storeLe(out.data() + footerLengthAt, footer.commitLength);
    storeLe(out.data() + footerGenerationAt, footer.generation);
    std::ranges::copy(footer.commitDigest, out.begin() + footerDigestAt);

    storeLe(out.data() + footerCrcAt, footerChecksum(out));
    return out;
}

Result<Footer> decodeFooter(std::span<const std::byte> data, std::uint64_t footerOffset) {
    if (data.size() < footerSize) {
        return fail(ErrorKind::Truncated, "footer truncated", footerOffset + data.size());
    }
    auto bytes = data.first<footerSize>();

    if (!std::ranges::equal(bytes.first<footerMagic.size()>(), footerMagic)) {
        return fail(ErrorKind::Malformed, "bad footer magic", footerOffset);
    }

    auto stored = loadLe<std::uint32_t>(bytes.data() + footerCrcAt);
    if (stored != footerChecksum(bytes)) {
        return fail(ErrorKind::Integrity, "footer checksum mismatch", footerOffset + footerCrcAt);
    }

    if (!allZero(bytes.subspan<footerReservedAt>())) {
        return fail(
            ErrorKind::Malformed,
            "footer reserved bytes not zero",
            footerOffset + footerReservedAt
        );
    }

    Footer footer;
    footer.commitOffset = loadLe<std::uint64_t>(bytes.data() + footerOffsetAt);
    footer.commitLength = loadLe<std::uint64_t>(bytes.data() + footerLengthAt);
    footer.generation = loadLe<std::uint64_t>(bytes.data() + footerGenerationAt);
    std::ranges::copy(
        bytes.subspan<footerDigestAt, commitDigestSize>(),
        footer.commitDigest.begin()
    );

    if (footer.commitLength < recordFramingSize) {
        return fail(
            ErrorKind::Malformed,
            "footer commit length shorter than record framing",
            footerOffset + footerLengthAt
        );
    }
    if (footer.commitOffset < superblockSize) {
        return fail(
            ErrorKind::Malformed,
            "footer commit offset inside superblock",
            footerOffset + footerOffsetAt
        );
    }

    auto commitEnd = checkedAdd(footer.commitOffset, footer.commitLength);
    if (!commitEnd || *commitEnd > footerOffset) {
        return fail(
            ErrorKind::Malformed,
            "footer commit record does not precede footer",
            footerOffset + footerOffsetAt
        );
    }
    return footer;
}

}
