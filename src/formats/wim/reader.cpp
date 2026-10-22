#include "formats/wim/reader.hpp"

#include "base/checked.hpp"

#include <unordered_set>
#include <utility>

namespace bale::wim {

namespace {

inline constexpr std::uint64_t maxReparseBytes = std::uint64_t{1} << 20;

struct SolidSpot {
    std::size_t run = 0;
    std::size_t resource = 0;
    std::uint64_t base = 0;
};

struct Found {
    std::uint32_t run = 0;
    std::uint32_t slot = 0;
    bool solid = false;
    std::uint64_t base = 0;
    std::uint64_t size = 0;
};

[[nodiscard]] Result<std::string>
readReparseTarget(const Resource& resource, const Found& found, const Node& node) {
    if (found.size > maxReparseBytes) {
        return fail(ErrorKind::LimitExceeded, "WIM reparse data exceeds limit");
    }
    std::size_t bytes = static_cast<std::size_t>(found.size);
    std::vector<std::byte> data(bytes);
    auto sink = [&data,
                 at = std::size_t{0}](std::span<const std::byte> chunk) mutable -> Result<void> {
        if (chunk.size() > data.size() - at) {
            return fail(ErrorKind::Malformed, "WIM reparse data overflows its buffer");
        }
        std::copy(chunk.begin(), chunk.end(), data.begin() + static_cast<std::ptrdiff_t>(at));
        at += chunk.size();
        return Result<void>{};
    };
    std::vector<std::byte> scratch(65536);
    auto streamed = resource.streamRange(found.base, found.size, scratch, sink);
    if (!streamed) {
        return std::unexpected(streamed.error());
    }
    return parseReparseTarget(data, node.reparseTag);
}

}

Reader::Reader(Reader&& other) noexcept :
    file_(std::move(other.file_)), limits_(other.limits_), compression_(other.compression_),
    images_(std::move(other.images_)), selected_(other.selected_), boot_(other.boot_),
    blobIndex_(std::move(other.blobIndex_)), resources_(std::move(other.resources_)),
    solidResources_(std::move(other.solidResources_)), names_(std::move(other.names_)),
    targets_(std::move(other.targets_)), entries_(std::move(other.entries_)),
    locations_(std::move(other.locations_)), totalBytes_(other.totalBytes_) {
    for (auto& resource : resources_) {
        resource.rebind(&file_);
    }
    for (auto& run : solidResources_) {
        for (auto& resource : run) {
            resource.rebind(&file_);
        }
    }
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        entries_[index].name = names_[index];
        entries_[index].linkTarget = targets_[index];
    }
}

Reader& Reader::operator=(Reader&& other) noexcept {
    if (this != &other) {
        file_ = std::move(other.file_);
        limits_ = other.limits_;
        compression_ = other.compression_;
        images_ = std::move(other.images_);
        selected_ = other.selected_;
        boot_ = other.boot_;
        blobIndex_ = std::move(other.blobIndex_);
        resources_ = std::move(other.resources_);
        solidResources_ = std::move(other.solidResources_);
        names_ = std::move(other.names_);
        targets_ = std::move(other.targets_);
        entries_ = std::move(other.entries_);
        locations_ = std::move(other.locations_);
        totalBytes_ = other.totalBytes_;
        for (auto& resource : resources_) {
            resource.rebind(&file_);
        }
        for (auto& run : solidResources_) {
            for (auto& resource : run) {
                resource.rebind(&file_);
            }
        }
        for (std::size_t index = 0; index < entries_.size(); ++index) {
            entries_[index].name = names_[index];
            entries_[index].linkTarget = targets_[index];
        }
    }
    return *this;
}

Result<Reader> Reader::open(File file, const Limits& limits, std::uint32_t imageIndex) {
    auto fileSize = file.size();
    if (!fileSize) {
        return std::unexpected(fileSize.error());
    }
    auto header = parseHeader(file, *fileSize);
    if (!header) {
        return std::unexpected(header.error());
    }
    if (header->imageCount > limits.maxImages) {
        return fail(ErrorKind::LimitExceeded, "WIM image count exceeds limit");
    }

    auto images = parseImageList(file, *header, limits);
    if (!images) {
        return std::unexpected(images.error());
    }

    // NOTE: an explicit --image index wins; otherwise the bootable image wins
    // when the header names one, and image 1 is the fallback. There is no
    // multi-image merge: one image is selected per open, so list, test,
    // extract and convert all see a single tree.
    std::uint32_t selected = imageIndex;
    if (selected == 0) {
        selected = (header->bootIndex >= 1 && header->bootIndex <= header->imageCount)
            ? header->bootIndex
            : 1;
    }
    if (selected < 1 || selected > header->imageCount) {
        return fail(ErrorKind::Malformed, "WIM image index is out of range");
    }

    auto table = parseLookup(file, *header, *fileSize, limits);
    if (!table) {
        return std::unexpected(table.error());
    }
    if (table->metadata.size() < header->imageCount) {
        return fail(ErrorKind::Malformed, "WIM is missing image metadata");
    }

    ResourceContext context{
        .version = header->version,
        .compression = header->compression,
        .chunkSize = header->chunkSize,
        .fileSize = *fileSize,
    };

    Reader reader(std::move(file), limits);
    reader.compression_ = header->compression;
    reader.images_ = std::move(*images);
    reader.selected_ = selected;
    reader.boot_ = header->bootIndex;

    for (const Blob& blob : table->blobs) {
        auto resource =
            Resource::open(reader.file_, blob.ref, context, limits, limits.maxTotalBytes);
        if (!resource) {
            return std::unexpected(resource.error());
        }
        BlobKey key;
        key.bytes = blob.hash;
        reader.blobIndex_[key] = reader.resources_.size();
        reader.resources_.push_back(*resource);
    }

    std::unordered_map<BlobKey, SolidSpot, BlobKeyHasher> solidIndex;
    reader.solidResources_.reserve(table->solidRuns.size());
    for (const SolidRun& run : table->solidRuns) {
        std::size_t runNumber = reader.solidResources_.size();
        std::vector<Resource> opened;
        for (const ResourceRef& ref : run.resources) {
            auto resource =
                Resource::open(reader.file_, ref, context, limits, limits.maxTotalBytes);
            if (!resource) {
                return std::unexpected(resource.error());
            }
            opened.push_back(*resource);
        }
        reader.solidResources_.push_back(std::move(opened));
        const std::vector<Resource>& stored = reader.solidResources_.back();
        for (const SolidBlob& blob : run.blobs) {
            BlobKey key;
            key.bytes = blob.hash;
            if (reader.blobIndex_.contains(key) || solidIndex.contains(key)) {
                continue;
            }
            std::uint64_t remaining = blob.offset;
            bool placed = false;
            for (std::size_t slot = 0; slot < stored.size(); ++slot) {
                auto end = checkedAdd(remaining, blob.size);
                if (!end) {
                    return fail(ErrorKind::Malformed, "WIM solid blob overflows");
                }
                if (*end <= stored[slot].uncompressedSize()) {
                    solidIndex[key] = {runNumber, slot, remaining};
                    placed = true;
                    break;
                }
                if (remaining < stored[slot].uncompressedSize()) {
                    return fail(ErrorKind::Malformed, "WIM solid blob is out of range");
                }
                remaining -= stored[slot].uncompressedSize();
            }
            if (!placed) {
                return fail(ErrorKind::Malformed, "WIM solid blob is out of range");
            }
        }
    }

    auto findBlob = [&](const std::array<std::byte, hashSize>& hash) -> Result<Found> {
        BlobKey key;
        key.bytes = hash;
        auto direct = reader.blobIndex_.find(key);
        if (direct != reader.blobIndex_.end()) {
            auto slot = checkedCast<std::uint32_t>(direct->second);
            if (!slot) {
                return fail(ErrorKind::Malformed, "WIM blob index is out of range");
            }
            const Resource& resource = reader.resources_[*slot];
            return Found{.slot = *slot, .size = resource.uncompressedSize()};
        }
        auto solid = solidIndex.find(key);
        if (solid == solidIndex.end()) {
            return fail(ErrorKind::Malformed, "WIM entry references no data");
        }
        const SolidSpot& spot = solid->second;
        auto run = checkedCast<std::uint32_t>(spot.run);
        auto slot = checkedCast<std::uint32_t>(spot.resource);
        if (!run || !slot) {
            return fail(ErrorKind::Malformed, "WIM solid index is out of range");
        }
        std::uint64_t size = 0;
        for (const SolidBlob& blob : table->solidRuns[spot.run].blobs) {
            if (blob.hash == hash) {
                size = blob.size;
                break;
            }
        }
        return Found{.run = *run, .slot = *slot, .solid = true, .base = spot.base, .size = size};
    };

    auto findResource = [&](const Found& found) -> Result<const Resource*> {
        if (found.solid) {
            if (found.run >= reader.solidResources_.size() ||
                found.slot >= reader.solidResources_[found.run].size()) {
                return fail(ErrorKind::Malformed, "WIM entry references no data");
            }
            return &reader.solidResources_[found.run][found.slot];
        }
        if (found.slot >= reader.resources_.size()) {
            return fail(ErrorKind::Malformed, "WIM entry references no data");
        }
        return &reader.resources_[found.slot];
    };

    auto meta = Resource::open(
        reader.file_,
        table->metadata[selected - 1],
        context,
        limits,
        limits.maxTotalBytes
    );
    if (!meta) {
        return std::unexpected(meta.error());
    }
    auto nodes = walkMetadata(*meta, limits);
    if (!nodes) {
        return std::unexpected(nodes.error());
    }

    std::unordered_set<std::string_view> seen;
    std::unordered_map<std::string_view, std::uint64_t> sizes;
    reader.names_.reserve(nodes->size());
    reader.targets_.reserve(nodes->size());
    reader.entries_.reserve(nodes->size());
    reader.locations_.reserve(nodes->size());

    for (const Node& node : *nodes) {
        if (!seen.insert(node.path).second) {
            continue;
        }
        reader.names_.push_back(node.path);
        Located located;
        std::uint64_t size = 0;
        if ((node.kind == EntryKind::Regular || node.kind == EntryKind::AlternateStream) &&
            node.hasData) {
            auto found = findBlob(node.hash);
            if (!found) {
                return std::unexpected(found.error());
            }
            if (found->size > limits.maxEntryBytes) {
                return fail(ErrorKind::LimitExceeded, "WIM entry exceeds size limit");
            }
            auto total = checkedAdd(reader.totalBytes_, found->size);
            if (!total || *total > limits.maxTotalBytes) {
                return fail(ErrorKind::LimitExceeded, "WIM total size exceeds limit");
            }
            reader.totalBytes_ = *total;
            located = {
                .run = found->run,
                .slot = found->slot,
                .base = found->base,
                .solid = found->solid,
                .valid = true
            };
            size = found->size;
        }
        if (node.kind == EntryKind::HardLink) {
            reader.targets_.push_back(node.linkTarget);
            auto known = sizes.find(reader.targets_.back());
            size = known != sizes.end() ? known->second : 0;
        } else if (node.kind == EntryKind::Symlink && node.hasReparse) {
            auto found = findBlob(node.reparseHash);
            if (!found) {
                return std::unexpected(found.error());
            }
            auto resource = findResource(*found);
            if (!resource) {
                return std::unexpected(resource.error());
            }
            auto target = readReparseTarget(**resource, *found, node);
            if (!target) {
                return std::unexpected(target.error());
            }
            reader.targets_.push_back(std::move(*target));
        } else {
            reader.targets_.emplace_back();
        }
        if (node.kind == EntryKind::Regular || node.kind == EntryKind::AlternateStream) {
            sizes[reader.names_.back()] = size;
        }
        reader.entries_.push_back(
            Entry{
                .name = {},
                .linkTarget = {},
                .size = size,
                .mtimeSeconds = node.mtimeSeconds,
                .mode = node.mode,
                .kind = node.kind,
            }
        );
        reader.locations_.push_back(located);
    }
    for (std::size_t index = 0; index < reader.entries_.size(); ++index) {
        reader.entries_[index].name = reader.names_[index];
        reader.entries_[index].linkTarget = reader.targets_[index];
    }
    return reader;
}

}
