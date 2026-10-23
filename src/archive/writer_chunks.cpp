#include "archive/chunk_pipeline.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"

#include <algorithm>
#include <array>
#include <limits>

namespace bale::archive {

namespace {

constexpr std::uint32_t maxReferences = std::numeric_limits<std::uint32_t>::max();

}

const IndexEntry*
Writer::ChunkTable::find(std::span<const IndexEntry> entries, const ChunkKey& key) const {
    if (slots_.empty()) {
        return nullptr;
    }

    std::size_t mask = slots_.size() - 1;
    for (std::size_t slot = slotFor(key);; slot = (slot + 1) & mask) {
        std::uint32_t stored = slots_[slot];
        if (stored == 0) {
            return nullptr;
        }
        if (entries[stored - 1].key == key) {
            return &entries[stored - 1];
        }
    }
}

void Writer::ChunkTable::insert(std::span<const IndexEntry> entries, std::uint32_t position) {
    if ((size_ + 1) * 2 > slots_.size()) {
        grow(entries);
    }

    std::size_t mask = slots_.size() - 1;
    std::size_t slot = slotFor(entries[position].key);
    while (slots_[slot] != 0) {
        slot = (slot + 1) & mask;
    }
    slots_[slot] = position + 1;
    ++size_;
}

std::size_t Writer::ChunkTable::slotFor(const ChunkKey& key) const {
    auto hash = loadLe<std::uint64_t>(key.digest.data()) ^ (key.length * 0x9E3779B97F4A7C15);
    return static_cast<std::size_t>(hash) & (slots_.size() - 1);
}

void Writer::ChunkTable::grow(std::span<const IndexEntry> entries) {
    std::vector<std::uint32_t> previous(std::max<std::size_t>(64, slots_.size() * 2), 0);
    previous.swap(slots_);

    std::size_t mask = slots_.size() - 1;
    for (std::uint32_t stored : previous) {
        if (stored == 0) {
            continue;
        }
        std::size_t slot = slotFor(entries[stored - 1].key);
        while (slots_[slot] != 0) {
            slot = (slot + 1) & mask;
        }
        slots_[slot] = stored;
    }
}

Result<void> Writer::failInOrder(const Error& error) {
    auto drained = pump(true);
    if (!drained) {
        return drained;
    }
    return poison(error);
}

Result<ChunkSlot*> Writer::acquireSlot() {
    while (pipeline_->full()) {
        auto event = pipeline_->next(true);
        if (!event) {
            return tl::unexpected<Error>(check().error());
        }
        auto handled = handle(*event);
        if (!handled) {
            return tl::unexpected<Error>(handled.error());
        }
    }
    return &pipeline_->freeSlot();
}

Result<void> Writer::submitChunk(std::size_t size) {
    if (chunks_.size() >= maxReferences) {
        return failInOrder(
            Error{.kind = ErrorKind::LimitExceeded, .what = "too many chunk references"}
        );
    }

    pipeline_->freeSlot().reference = chunks_.size();
    chunks_.emplace_back();
    contentBytes_ += size;
    pipeline_->submit(size);
    return pump(false);
}

Result<void> Writer::pump(bool drain) {
    while (auto event = pipeline_->next(drain)) {
        auto handled = handle(*event);
        if (!handled) {
            return handled;
        }
    }
    return check();
}

Result<void> Writer::handle(const PipelineEvent& event) {
    ChunkSlot& slot = *event.slot;
    if (event.step == PipelineStep::Append) {
        auto appended = appendChunk(slot);
        if (!appended) {
            return appended;
        }
        pipeline_->release();
        return {};
    }

    chunks_[slot.reference] = slot.key;
    if (encrypted_) {
        // NOTE: no cross-chunk dedup in encrypted mode, not even within one run beyond the
        // NOTE: caller's own coalescing; every chunk gets a fresh random object id so equal
        // NOTE: plaintexts produce unrelated ciphertext. Growth-indistinguishability pinned by
        // test.
        slot.indexPosition = static_cast<std::uint32_t>(index_.size());
        ChunkKey objectKey{
            .algorithm = HashAlgorithm::EncryptedObject,
            .length = slot.key.length,
        };
        index_.push_back(IndexEntry{.key = objectKey});
        objectIds_.emplace_back();
        pipeline_->decided(true);
        return {};
    }
    if (table_.find(index_, slot.key) != nullptr) {
        slot.indexPosition.reset();
        pipeline_->decided(false);
        return {};
    }

    slot.indexPosition = static_cast<std::uint32_t>(index_.size());
    index_.push_back(IndexEntry{.key = slot.key});
    table_.insert(index_, *slot.indexPosition);
    pipeline_->decided(true);
    return {};
}

Result<void> Writer::appendChunk(ChunkSlot& slot) {
    if (slot.error) {
        return poison(*slot.error);
    }
    if (!slot.indexPosition) {
        return {};
    }
    if (encrypted_) {
        return appendChunkEncrypted(slot);
    }

    auto descriptor = encodeDataDescriptor(slot.key, descriptor_);
    if (!descriptor) {
        return poison(descriptor.error());
    }
    auto span = writeRecord(
        RecordType::Data,
        descriptor_,
        slot.stored(),
        slot.codec,
        descriptor_.size() + slot.size
    );
    if (!span) {
        return tl::unexpected<Error>(span.error());
    }

    IndexEntry& entry = index_[*slot.indexPosition];
    entry.recordOffset = span->offset;
    entry.recordLength = span->length;
    entry.codec = slot.codec;
    return {};
}

Result<void>
Writer::addFile(std::string_view path, const File& source, const EntryAttributes& attributes) {
    if (options_.chunkPolicy == ChunkPolicy::Cdc) {
        return addFileCdc(path, source, attributes);
    }

    auto attributesValid = checkAttributes(attributes);
    if (!attributesValid) {
        return attributesValid;
    }

    auto entry = beginEntry(path, EntryKind::Regular);
    if (!entry) {
        return tl::unexpected<Error>(entry.error());
    }
    std::size_t position = entries_.size() - 1;

    std::uint64_t length = 0;
    while (true) {
        auto slot = acquireSlot();
        if (!slot) {
            return tl::unexpected<Error>(slot.error());
        }
        std::span<std::byte> buffer = (*slot)->input;
        std::size_t filled = 0;
        while (filled < buffer.size()) {
            auto count = source.readAt(length + filled, buffer.subspan(filled));
            if (!count) {
                return failInOrder(count.error());
            }
            if (*count == 0) {
                break;
            }
            filled += *count;
        }
        if (filled == 0) {
            break;
        }

        auto submitted = submitChunk(filled);
        if (!submitted) {
            return submitted;
        }
        length += filled;
        if (filled < buffer.size()) {
            break;
        }
    }

    PendingEntry& stored = entries_[position];
    stored.length = length;
    stored.chunkCount = static_cast<std::uint32_t>(chunks_.size() - stored.firstChunk);
    stored.mtimeNanoseconds = attributes.mtimeNanoseconds;
    stored.mode = attributes.mode;
    return {};
}

Result<void> Writer::addBytes(
    std::string_view path,
    std::span<const std::byte> data,
    const EntryAttributes& attributes
) {
    if (options_.chunkPolicy == ChunkPolicy::Cdc) {
        auto begun = beginFile(path, attributes);
        if (!begun) {
            return begun;
        }

        auto written = writeFile(data);
        if (!written) {
            return written;
        }
        return endFile();
    }

    auto attributesValid = checkAttributes(attributes);
    if (!attributesValid) {
        return attributesValid;
    }

    auto entry = beginEntry(path, EntryKind::Regular);
    if (!entry) {
        return tl::unexpected<Error>(entry.error());
    }
    std::size_t position = entries_.size() - 1;

    for (std::size_t at = 0; at < data.size(); at += options_.chunkSize) {
        auto slot = acquireSlot();
        if (!slot) {
            return tl::unexpected<Error>(slot.error());
        }
        auto chunk = data.subspan(at, std::min<std::size_t>(options_.chunkSize, data.size() - at));
        std::ranges::copy(chunk, (*slot)->input.begin());
        auto submitted = submitChunk(chunk.size());
        if (!submitted) {
            return submitted;
        }
    }

    PendingEntry& stored = entries_[position];
    stored.length = data.size();
    stored.chunkCount = static_cast<std::uint32_t>(chunks_.size() - stored.firstChunk);
    stored.mtimeNanoseconds = attributes.mtimeNanoseconds;
    stored.mode = attributes.mode;
    return {};
}

Result<void> Writer::beginFile(std::string_view path, const EntryAttributes& attributes) {
    auto attributesValid = checkAttributes(attributes);
    if (!attributesValid) {
        return attributesValid;
    }

    auto entry = beginEntry(path, EntryKind::Regular);
    if (!entry) {
        return tl::unexpected<Error>(entry.error());
    }
    (*entry)->mtimeNanoseconds = attributes.mtimeNanoseconds;
    (*entry)->mode = attributes.mode;
    openFile_ = OpenFile{
        .position = entries_.size() - 1,
        .cdc = CdcSplitter(options_.cdc),
    };
    return {};
}

Result<void> Writer::writeFile(std::span<const std::byte> data) {
    auto usable = check();
    if (!usable) {
        return usable;
    }
    if (!openFile_) {
        return fail(ErrorKind::Malformed, "no file entry is open");
    }
    if (options_.chunkPolicy == ChunkPolicy::Cdc) {
        return writeFileCdc(data);
    }

    OpenFile& open = *openFile_;
    while (!data.empty()) {
        auto slot = acquireSlot();
        if (!slot) {
            return tl::unexpected<Error>(slot.error());
        }

        std::span<std::byte> buffer = (*slot)->input;
        auto room = std::min(data.size(), buffer.size() - open.filled);
        std::ranges::copy(
            data.first(room),
            buffer.begin() + static_cast<std::ptrdiff_t>(open.filled)
        );
        open.filled += room;
        open.length += room;
        data = data.subspan(room);

        if (open.filled == buffer.size()) {
            open.filled = 0;
            auto submitted = submitChunk(buffer.size());
            if (!submitted) {
                return submitted;
            }
        }
    }
    return {};
}

Result<void> Writer::endFile() {
    auto usable = check();
    if (!usable) {
        return usable;
    }
    if (!openFile_) {
        return fail(ErrorKind::Malformed, "no file entry is open");
    }

    OpenFile open = *openFile_;
    openFile_.reset();
    if (open.filled != 0) {
        auto submitted = submitChunk(open.filled);
        if (!submitted) {
            return submitted;
        }
    }

    PendingEntry& stored = entries_[open.position];
    stored.length = open.length;
    stored.chunkCount = static_cast<std::uint32_t>(chunks_.size() - stored.firstChunk);
    return {};
}

Result<void> Writer::addWalked(const WalkEntry& entry) {
    EntryAttributes attributes{
        .mtimeNanoseconds = entry.mtimeNanoseconds,
        .mode = entry.mode,
    };
    switch (entry.kind) {
    case WalkKind::Directory:
        return addDirectory(entry.path, attributes);
    case WalkKind::Regular:
        return addFile(entry.path, *entry.file, attributes);
    case WalkKind::Symlink:
        return addSymlink(entry.path, entry.target, attributes);
    case WalkKind::HardLink:
        return addHardLink(entry.path, entry.target);
    }
    return fail(ErrorKind::Unsupported, "unknown walked entry kind");
}

Result<void>
Writer::addTree(const std::filesystem::path& root, const std::filesystem::path& exclude) {
    auto usable = check();
    if (!usable) {
        return usable;
    }

    WalkOptions walkOptions{
        .limits = options_.limits,
        .exclude = exclude,
    };
    auto walker = TreeWalker::open(root, walkOptions);
    if (!walker) {
        return tl::unexpected<Error>(walker.error());
    }

    Result<void> result;
    while (result) {
        auto next = walker->next();
        if (!next) {
            result = tl::unexpected<Error>(next.error());
            break;
        }
        if (*next == nullptr) {
            break;
        }
        result = addWalked(**next);
    }

    skipped_.insert(skipped_.end(), walker->skipped().begin(), walker->skipped().end());
    return result;
}

Result<void>
Writer::addFileCdc(std::string_view path, const File& source, const EntryAttributes& attributes) {
    auto begun = beginFile(path, attributes);
    if (!begun) {
        return begun;
    }

    std::array<std::byte, 65536> staging;
    std::uint64_t offset = 0;
    while (true) {
        auto count = source.readAt(offset, staging);
        if (!count) {
            return failInOrder(count.error());
        }
        if (*count == 0) {
            break;
        }

        auto written = writeFile(std::span(staging).first(*count));
        if (!written) {
            return written;
        }
        offset += *count;
    }
    return endFile();
}

Result<void> Writer::writeFileCdc(std::span<const std::byte> data) {
    if (!openFile_) {
        return fail(ErrorKind::Malformed, "no file entry is open");
    }
    OpenFile& open = *openFile_;

    while (!data.empty()) {
        auto slot = acquireSlot();
        if (!slot) {
            return tl::unexpected<Error>(slot.error());
        }

        std::span<std::byte> buffer = (*slot)->input;
        bool cut = false;
        while (!data.empty() && !cut) {
            buffer[open.filled] = data[0];
            std::byte value = data[0];
            data = data.subspan(1);
            ++open.filled;
            ++open.length;
            cut = open.cdc.feed(value);
        }

        if (cut) {
            std::size_t complete = open.filled;
            open.cdc.nextChunk();
            open.filled = 0;
            auto submitted = submitChunk(complete);
            if (!submitted) {
                return submitted;
            }
        }
    }
    return {};
}

}
