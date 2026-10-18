#include "archive/commit.hpp"
#include "archive/reader.hpp"
#include "base/endian.hpp"
#include "checksum/blake3.hpp"
#include "checksum/crc.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"
#include "fuzz/memory_file.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t recordCrcAt = 36;
constexpr std::size_t superblockCrcAt = 56;
constexpr std::size_t footerOffsetAt = 8;
constexpr std::size_t footerLengthAt = 16;
constexpr std::size_t footerDigestAt = 32;
constexpr std::size_t footerCrcAt = 64;
constexpr std::uint64_t maxStreamedBytes = std::uint64_t{32} << 20;

using Bytes = std::vector<std::byte>;

bool startsWith(
    std::span<const std::byte> bytes,
    std::size_t at,
    std::span<const std::byte> magic
) {
    return at <= bytes.size() && magic.size() <= bytes.size() - at &&
        std::ranges::equal(bytes.subspan(at, magic.size()), magic);
}

std::span<std::byte> recordPayload(Bytes& bytes, std::uint64_t offset, std::uint64_t length) {
    if (!bale::fitsWithin<std::uint64_t>(offset, length, bytes.size()) ||
        length < bale::recordFramingSize || !startsWith(bytes, offset, bale::recordMagic)) {
        return {};
    }
    return std::span(bytes).subspan(
        offset + bale::recordPrefixSize,
        length - bale::recordFramingSize
    );
}

void sealPayload(Bytes& bytes, std::span<std::byte> payload) {
    auto* trailer = payload.data() + payload.size();
    if (trailer + 4 > bytes.data() + bytes.size()) {
        return;
    }
    bale::storeLe(trailer, bale::Crc32c::of(payload));
}

std::vector<std::size_t> sealRecords(Bytes& bytes) {
    std::vector<std::size_t> footers;
    std::size_t position = bale::superblockSize;
    while (position < bytes.size()) {
        if (startsWith(bytes, position, bale::footerMagic) &&
            bytes.size() - position >= bale::footerSize) {
            footers.push_back(position);
            position += bale::footerSize;
            continue;
        }
        if (!startsWith(bytes, position, bale::recordMagic) ||
            bytes.size() - position < bale::recordFramingSize) {
            break;
        }

        auto* prefix = bytes.data() + position;
        bale::storeLe(prefix + recordCrcAt, std::uint32_t{0});
        bale::storeLe(
            prefix + recordCrcAt,
            bale::Crc32c::of(std::span(prefix, bale::recordPrefixSize))
        );

        auto length = bale::loadLe<std::uint64_t>(prefix + 8);
        if (length > bytes.size() - position - bale::recordFramingSize) {
            break;
        }
        sealPayload(bytes, std::span(bytes).subspan(position + bale::recordPrefixSize, length));
        position += bale::recordFramingSize + length;
    }
    return footers;
}

void sealDigest(
    Bytes& bytes,
    const bale::archive::RecordReference& reference,
    bale::HashDomain domain,
    bale::Blake3Digest& digest
) {
    auto payload = recordPayload(bytes, reference.offset, reference.length);
    if (payload.data() != nullptr) {
        digest = bale::Blake3::of(domain, payload);
    }
}

void sealFooter(Bytes& bytes, std::size_t footer, const bale::Blake3Digest* previous) {
    auto* fields = bytes.data() + footer;
    auto commitOffset = bale::loadLe<std::uint64_t>(fields + footerOffsetAt);
    auto commitLength = bale::loadLe<std::uint64_t>(fields + footerLengthAt);
    auto payload = recordPayload(bytes, commitOffset, commitLength);
    if (payload.data() != nullptr) {
        auto commit = bale::archive::decodeCommit(payload, 0);
        if (commit) {
            sealDigest(
                bytes,
                commit->manifest,
                bale::HashDomain::Manifest,
                commit->manifest.digest
            );
            sealDigest(bytes, commit->index, bale::HashDomain::Index, commit->index.digest);
            if (previous != nullptr && commit->generation > 1) {
                commit->previous = *previous;
            }

            Bytes encoded;
            if (bale::archive::encodeCommit(*commit, encoded) && encoded.size() == payload.size()) {
                std::ranges::copy(encoded, payload.begin());
                sealPayload(bytes, payload);
            }
        }

        auto digest = bale::Blake3::of(bale::HashDomain::Commit, payload);
        std::ranges::copy(digest, fields + footerDigestAt);
    }

    bale::storeLe(fields + footerCrcAt, std::uint32_t{0});
    bale::storeLe(fields + footerCrcAt, bale::Crc32c::of(std::span(fields, bale::footerSize)));
}

void seal(Bytes& bytes) {
    if (bytes.size() < bale::superblockSize) {
        return;
    }
    bale::storeLe(
        bytes.data() + superblockCrcAt,
        bale::Crc32c::of(std::span(bytes).first(superblockCrcAt))
    );

    auto footers = sealRecords(bytes);
    bale::Blake3Digest previous{};
    const bale::Blake3Digest* parent = nullptr;
    for (std::size_t footer : footers) {
        sealFooter(bytes, footer, parent);
        std::copy_n(bytes.data() + footer + footerDigestAt, previous.size(), previous.begin());
        parent = &previous;
    }
}

void readArchive(std::span<const std::byte> bytes, std::uint64_t footerScanBlockSize) {
    auto file = bale::fuzz::memoryFile(bytes);
    if (!file) {
        return;
    }

    bale::archive::ReaderOptions options;
    options.limits.maxEntries = 4096;
    options.limits.maxPathBytes = 1024;
    options.limits.maxDepth = 32;
    options.footerScanBlockSize = footerScanBlockSize;
    options.maxMetadataBytes = std::uint64_t{1} << 20;
    options.maxGenerations = 64;

    auto reader = bale::archive::Reader::open(std::move(*file), options);
    if (!reader) {
        return;
    }

    std::uint64_t streamed = 0;
    auto sink = [&streamed](std::span<const std::byte> chunk) -> bale::Result<void> {
        streamed += chunk.size();
        if (streamed > maxStreamedBytes) {
            return bale::fail(bale::ErrorKind::LimitExceeded, "fuzz output budget exhausted");
        }
        return {};
    };
    for (const auto& entry : reader->manifest().entries) {
        if (entry.kind != bale::archive::EntryKind::Regular) {
            continue;
        }
        auto streamedEntry = reader->streamFile(entry, sink);
        if (!streamedEntry && streamedEntry.error().kind == bale::ErrorKind::LimitExceeded) {
            break;
        }
        static_cast<void>(bale::archive::findEntry(reader->manifest().entries, entry.path));
    }

    static_cast<void>(reader->verify(bale::archive::VerifyMode::Structure));
    if (streamed <= maxStreamedBytes) {
        static_cast<void>(reader->verify(bale::archive::VerifyMode::Content));
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    Bytes bytes(input.begin(), input.end());
    seal(bytes);

    std::uint64_t window = (size & 1) == 0 ? std::uint64_t{1} << 20 : 96 + size % 512;
    readArchive(bytes, window);
    return 0;
}
