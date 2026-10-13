#include "archive/chunk_pipeline.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"

#include <algorithm>
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
            return std::unexpected(check().error());
        }
        auto handled = handle(*event);
        if (!handled) {
            return std::unexpected(handled.error());
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
        return std::unexpected(span.error());
    }

    IndexEntry& entry = index_[*slot.indexPosition];
    entry.recordOffset = span->offset;
    entry.recordLength = span->length;
    entry.codec = slot.codec;
    return {};
}

Result<void>
Writer::addFile(std::string_view path, const File& source, const EntryAttributes& attributes) {
    auto attributesValid = checkAttributes(attributes);
    if (!attributesValid) {
        return attributesValid;
    }

    auto entry = beginEntry(path, EntryKind::Regular);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    std::size_t position = entries_.size() - 1;

    std::uint64_t length = 0;
    while (true) {
        auto slot = acquireSlot();
        if (!slot) {
            return std::unexpected(slot.error());
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
    auto attributesValid = checkAttributes(attributes);
    if (!attributesValid) {
        return attributesValid;
    }

    auto entry = beginEntry(path, EntryKind::Regular);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    std::size_t position = entries_.size() - 1;

    for (std::size_t at = 0; at < data.size(); at += options_.chunkSize) {
        auto slot = acquireSlot();
        if (!slot) {
            return std::unexpected(slot.error());
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

}
