#include "formats/iso/reader.hpp"

#include "formats/iso/directory.hpp"
#include "formats/iso/eltorito.hpp"
#include "formats/iso/volume.hpp"

#include <string>
#include <unordered_set>
#include <utility>

namespace bale::iso {

namespace {

constexpr std::uint32_t bootFileMode = 0100444;

}

Result<Reader> Reader::open(File file, const Limits& limits) {
    auto size = file.size();
    if (!size) {
        return tl::unexpected<Error>(size.error());
    }

    auto image = isIsoImage(file, *size);
    if (!image) {
        return tl::unexpected<Error>(image.error());
    }
    if (!*image) {
        return fail(ErrorKind::Malformed, "not an ISO 9660 image");
    }
    auto volume = parseVolumes(file, *size, limits);
    if (!volume) {
        return tl::unexpected<Error>(volume.error());
    }

    bool sawRockRidge = false;
    auto nodes =
        walkTree(file, *size, volume->rootExtent, volume->rootSize, false, limits, sawRockRidge);
    if (!nodes) {
        return tl::unexpected<Error>(nodes.error());
    }

    // NOTE: Rock Ridge names win over Joliet because they preserve case,
    // modes and symlinks; the Joliet tree is only a fallback when the
    // primary tree carries no Rock Ridge data at all.
    if (!sawRockRidge && volume->hasJoliet) {
        auto joliet = walkTree(
            file,
            *size,
            volume->jolietExtent,
            volume->jolietSize,
            true,
            limits,
            sawRockRidge
        );
        if (!joliet) {
            return tl::unexpected<Error>(joliet.error());
        }
        nodes = std::move(joliet);
    }

    if (volume->bootCatalog.has_value()) {
        auto images = parseBootCatalog(file, *size, volume->bootCatalog.value_or(0), limits);
        if (!images) {
            return tl::unexpected<Error>(images.error());
        }
        std::unordered_set<std::string_view> taken;
        if (!images->empty()) {
            taken.reserve(nodes->size() + images->size());
            for (const Node& node : *nodes) {
                taken.insert(node.path);
            }
        }
        std::uint64_t number = 0;
        for (const BootImage& boot : *images) {
            ++number;
            std::string name = "[BOOT]/BootImage-" + std::to_string(number) + ".img";
            if (!taken.insert(name).second) {
                return fail(ErrorKind::Malformed, "El Torito image name collides with a file");
            }
            auto start = sectorOffset(boot.extent, Error::noOffset);
            if (!start) {
                return tl::unexpected<Error>(start.error());
            }
            Node node;
            node.path = std::move(name);
            node.size = boot.size;
            node.mode = bootFileMode;
            node.extents.push_back(Extent{.offset = *start, .length = boot.size});
            nodes->push_back(std::move(node));
        }
    }

    Reader reader(std::move(file), limits);
    auto added = reader.addNodes(std::move(*nodes));
    if (!added) {
        return tl::unexpected<Error>(added.error());
    }
    return reader;
}

Result<void> Reader::addNodes(std::vector<Node>&& others) {
    for (auto& other : others) {
        if (entries_.size() >= limits_.maxEntries) {
            return fail(ErrorKind::LimitExceeded, "ISO entry count exceeds limit");
        }
        if (other.size > limits_.maxEntryBytes) {
            return fail(ErrorKind::LimitExceeded, "ISO entry exceeds size limit");
        }
        auto total = checkedAdd(totalBytes_, other.size);
        if (!total || *total > limits_.maxTotalBytes) {
            return fail(ErrorKind::LimitExceeded, "ISO total size exceeds limit");
        }
        totalBytes_ = *total;

        std::size_t begin = extents_.size();
        for (const Extent& extent : other.extents) {
            extents_.push_back(extent);
        }
        names_.push_back(std::move(other.path));
        targets_.push_back(std::move(other.target));
        entries_.push_back(
            Entry{
                .name = names_.back(),
                .linkTarget = targets_.back(),
                .size = other.size,
                .mtimeSeconds = other.mtimeSeconds,
                .mode = other.mode,
                .kind = other.kind,
                .extentBegin = begin,
                .extentEnd = extents_.size(),
            }
        );
    }

    // NOTE: names_ may have reallocated while indexing, which invalidates the
    // string_view names stored in entries_, so rebind every view to its owner.
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        entries_[index].name = names_[index];
        entries_[index].linkTarget = targets_[index];
    }
    return {};
}

}
