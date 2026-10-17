#include "archive/chunk.hpp"
#include "archive/commit.hpp"
#include "archive/index.hpp"
#include "archive/manifest.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"
#include "fuzz/memory_file.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

constexpr std::size_t recordCrcAt = 36;
constexpr std::size_t superblockCrcAt = 56;
constexpr std::size_t footerCrcAt = 64;
constexpr std::uint64_t footerOffset = std::uint64_t{1} << 40;

bale::Limits manifestLimits() {
    bale::Limits limits;
    limits.maxEntries = 4096;
    limits.maxPathBytes = 1024;
    limits.maxDepth = 32;
    return limits;
}

constexpr bale::RecordLimits recordLimits{
    .maxPayloadLength = std::uint64_t{1} << 20,
    .maxDecodedLength = std::uint64_t{1} << 20,
};

void require(bool condition) {
    if (!condition) {
        __builtin_trap();
    }
}

void checkManifest(std::span<const std::byte> payload) {
    bale::archive::Manifest manifest;
    if (!bale::archive::decodeManifest(payload, 0, manifestLimits(), manifest)) {
        return;
    }

    for (const auto& entry : manifest.entries) {
        require(entry.firstChunk + std::uint64_t{entry.chunkCount} <= manifest.chunks.size());
    }

    std::vector<std::byte> encoded;
    require(bale::archive::encodeManifest(manifest, encoded).has_value());
    bale::archive::Manifest again;
    require(bale::archive::decodeManifest(encoded, 0, manifestLimits(), again).has_value());
    require(again.entries.size() == manifest.entries.size());
    require(again.chunks == manifest.chunks);
}

void checkIndex(std::span<const std::byte> payload) {
    std::vector<bale::archive::IndexEntry> entries;
    if (!bale::archive::decodeIndex(payload, 0, 4096, entries)) {
        return;
    }

    std::vector<std::byte> encoded;
    require(bale::archive::encodeIndex(entries, encoded).has_value());
    std::vector<bale::archive::IndexEntry> again;
    require(bale::archive::decodeIndex(encoded, 0, 4096, again).has_value());
    require(again.size() == entries.size());
    for (const auto& entry : entries) {
        require(bale::archive::findChunk(again, entry.key) != nullptr);
    }
}

void checkCommit(std::span<const std::byte> payload) {
    auto commit = bale::archive::decodeCommit(payload, 0);
    if (!commit) {
        return;
    }

    std::vector<std::byte> encoded;
    require(bale::archive::encodeCommit(*commit, encoded).has_value());
    auto again = bale::archive::decodeCommit(encoded, 0);
    require(again.has_value());
    require(again->generation == commit->generation);
    require(again->manifest.offset == commit->manifest.offset);
    require(again->index.digest == commit->index.digest);
}

void checkDataPayload(std::span<const std::byte> payload) {
    auto data = bale::archive::decodeDataPayload(payload, 0);
    if (!data) {
        return;
    }

    std::vector<std::byte> descriptor;
    require(bale::archive::encodeDataDescriptor(data->key, descriptor).has_value());
    auto again = bale::archive::decodeDataPayload(descriptor, 0);
    require(again.has_value());
    require(again->key == data->key);
}

void checkPayload(std::span<const std::byte> payload) {
    checkManifest(payload);
    checkIndex(payload);
    checkCommit(payload);
    checkDataPayload(payload);
}

void checkSuperblock(std::span<const std::byte> input) {
    if (input.size() < bale::superblockSize) {
        return;
    }

    std::array<std::byte, bale::superblockSize> block{};
    std::ranges::copy(input.first<bale::superblockSize>(), block.begin());
    bale::storeLe(
        block.data() + superblockCrcAt,
        bale::Crc32c::of(std::span(block).first(superblockCrcAt))
    );

    auto decoded = bale::decodeSuperblock(block);
    if (decoded) {
        require(bale::encodeSuperblock(*decoded) == block);
    }
}

void checkFooter(std::span<const std::byte> input) {
    if (input.size() < bale::footerSize) {
        return;
    }

    std::array<std::byte, bale::footerSize> footer{};
    std::ranges::copy(input.first<bale::footerSize>(), footer.begin());
    bale::storeLe(footer.data() + footerCrcAt, std::uint32_t{0});
    bale::storeLe(footer.data() + footerCrcAt, bale::Crc32c::of(footer));

    auto decoded = bale::decodeFooter(footer, footerOffset);
    if (decoded) {
        require(bale::encodeFooter(*decoded) == footer);
    }
}

void checkRecord(std::span<const std::byte> input) {
    static_cast<void>(bale::decodeRecord(input, recordLimits));
    if (input.size() < bale::recordFramingSize ||
        !std::ranges::equal(input.first(bale::recordMagic.size()), bale::recordMagic)) {
        return;
    }

    std::vector<std::byte> fixed(input.begin(), input.end());
    bale::storeLe(fixed.data() + recordCrcAt, std::uint32_t{0});
    bale::storeLe(
        fixed.data() + recordCrcAt,
        bale::Crc32c::of(std::span(fixed).first(bale::recordPrefixSize))
    );

    auto length = bale::loadLe<std::uint64_t>(fixed.data() + 8);
    if (length <= fixed.size() - bale::recordFramingSize) {
        auto payload = std::span(fixed).subspan(bale::recordPrefixSize, length);
        bale::storeLe(fixed.data() + bale::recordPrefixSize + length, bale::Crc32c::of(payload));
    }

    auto record = bale::decodeRecord(fixed, recordLimits);
    if (!record) {
        return;
    }
    require(record->size <= fixed.size());
    checkPayload(record->payload);
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    checkSuperblock(input);
    checkFooter(input);
    checkRecord(input);
    checkPayload(input);
    return 0;
}
