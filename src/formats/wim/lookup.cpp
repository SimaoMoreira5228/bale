#include "formats/wim/lookup.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <utility>

namespace bale::wim {

namespace {

struct RawEntry {
    ResourceRef ref;
    std::uint16_t part = 0;
    std::uint32_t refcount = 0;
    std::array<std::byte, hashSize> hash{};
};

[[nodiscard]] bool isZeroHash(const std::array<std::byte, hashSize>& hash) {
    for (std::byte unit : hash) {
        if (unit != std::byte{0}) {
            return false;
        }
    }
    return true;
}

struct HashKey {
    std::array<std::byte, hashSize> bytes{};

    bool operator==(const HashKey& other) const {
        return bytes == other.bytes;
    }
};

struct HashKeyHasher {
    std::size_t operator()(const HashKey& key) const noexcept {
        std::size_t folded = 0;
        for (std::size_t index = 0; index < key.bytes.size(); ++index) {
            folded = folded * 1315423911U + static_cast<unsigned char>(key.bytes[index]);
        }
        return folded;
    }
};

}

Result<Lookup>
parseLookup(const File& file, const Header& header, std::uint64_t fileSize, const Limits& limits) {
    if ((header.lookup.flags & resFlagSpanned) != 0) {
        return fail(
            ErrorKind::Unsupported,
            "split WIM archives are not supported",
            header.lookup.offset
        );
    }
    if ((header.lookup.flags & resFlagCompressed) != 0) {
        return fail(
            ErrorKind::Unsupported,
            "compressed WIM lookup tables are not supported",
            header.lookup.offset
        );
    }
    if (header.lookup.sizeInWim != header.lookup.uncompressed) {
        return fail(ErrorKind::Malformed, "WIM lookup table size mismatch", header.lookup.offset);
    }
    if (header.lookup.sizeInWim > limits.maxLookupBytes) {
        return fail(ErrorKind::LimitExceeded, "WIM lookup table exceeds limit");
    }
    if (header.lookup.sizeInWim % blobEntrySize != 0) {
        return fail(ErrorKind::Malformed, "WIM lookup table has a partial entry");
    }

    std::uint64_t count = header.lookup.sizeInWim / blobEntrySize;
    if (count > limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "WIM lookup table exceeds limit");
    }
    std::size_t tableBytes = static_cast<std::size_t>(header.lookup.sizeInWim);
    std::vector<std::byte> table(tableBytes);
    auto read = file.readExactAt(header.lookup.offset, std::span(table));
    if (!read) {
        return std::unexpected(read.error());
    }

    std::vector<RawEntry> raw;
    raw.reserve(static_cast<std::size_t>(count));
    for (std::uint64_t index = 0; index < count; ++index) {
        const std::byte* entry = table.data() + index * blobEntrySize;
        std::uint64_t size = 0;
        for (std::size_t part = 0; part < 7; ++part) {
            size |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(entry[part]))
                << (part * 8);
        }
        RawEntry parsed;
        parsed.ref.offset = loadLe<std::uint64_t>(entry + 8);
        parsed.ref.sizeInWim = size;
        parsed.ref.uncompressed = loadLe<std::uint64_t>(entry + 16);
        parsed.ref.flags = std::to_integer<std::uint8_t>(entry[7]);
        parsed.part = loadLe<std::uint16_t>(entry + 24);
        parsed.refcount = loadLe<std::uint32_t>(entry + 26);
        for (std::size_t part = 0; part < hashSize; ++part) {
            parsed.hash[part] = entry[30 + part];
        }
        if ((parsed.ref.flags & resFlagSolid) != 0 && header.version != versionSolid) {
            parsed.ref.flags = static_cast<std::uint8_t>(parsed.ref.flags & ~resFlagSolid);
        }
        // NOTE: solid members address their resource, not the file: their
        // offsets are base positions inside the solid resource, so the file
        // range check does not apply to them. Placement against the owning
        // resource happens when the reader resolves blobs.
        bool isSolidMember =
            (parsed.ref.flags & resFlagSolid) != 0 && parsed.ref.uncompressed != solidResourceMagic;
        if (!isSolidMember && !fitsWithin(parsed.ref.offset, parsed.ref.sizeInWim, fileSize)) {
            return fail(ErrorKind::Malformed, "WIM blob is out of range", parsed.ref.offset);
        }
        // NOTE: resource markers of a solid run carry a zero hash by design;
        // only real blob entries are subject to the emptiness filters.
        bool isSolidMarker =
            (parsed.ref.flags & resFlagSolid) != 0 && parsed.ref.uncompressed == solidResourceMagic;
        if (parsed.part != 1) {
            continue;
        }
        if (!isSolidMarker && (isZeroHash(parsed.hash) || parsed.ref.sizeInWim == 0)) {
            continue;
        }
        raw.push_back(parsed);
    }

    Lookup lookup;
    std::unordered_map<HashKey, std::size_t, HashKeyHasher> byHash;

    std::size_t index = 0;
    while (index < raw.size()) {
        if ((raw[index].ref.flags & resFlagSolid) == 0) {
            const RawEntry& entry = raw[index];
            if ((entry.ref.flags & resFlagMetadata) != 0) {
                if (entry.refcount == 0) {
                    ++index;
                    continue;
                }
                if (entry.refcount != 1) {
                    return fail(
                        ErrorKind::Malformed,
                        "WIM metadata is shared between images",
                        entry.ref.offset
                    );
                }
                lookup.metadata.push_back(entry.ref);
            } else {
                HashKey key;
                key.bytes = entry.hash;
                if (!byHash.contains(key)) {
                    byHash[key] = lookup.blobs.size();
                    Blob blob;
                    blob.ref = entry.ref;
                    blob.part = entry.part;
                    blob.refcount = entry.refcount;
                    blob.hash = entry.hash;
                    lookup.blobs.push_back(blob);
                }
            }
            ++index;
            continue;
        }

        std::size_t runEnd = index;
        while (runEnd < raw.size() && (raw[runEnd].ref.flags & resFlagSolid) != 0) {
            ++runEnd;
        }
        SolidRun run;
        for (std::size_t cursor = index; cursor < runEnd; ++cursor) {
            const RawEntry& entry = raw[cursor];
            if (entry.ref.uncompressed == solidResourceMagic) {
                run.resources.push_back(entry.ref);
                continue;
            }
            if ((entry.ref.flags & resFlagMetadata) != 0) {
                return fail(
                    ErrorKind::Unsupported,
                    "WIM image metadata in solid resources is not supported",
                    entry.ref.offset
                );
            }
            SolidBlob blob;
            blob.offset = entry.ref.offset;
            blob.size = entry.ref.sizeInWim;
            blob.hash = entry.hash;
            run.blobs.push_back(blob);
        }
        if (run.resources.empty()) {
            return fail(
                ErrorKind::Malformed,
                "WIM solid run holds no resource",
                raw[index].ref.offset
            );
        }
        lookup.solidRuns.push_back(std::move(run));
        index = runEnd;
    }
    return lookup;
}

}
