#include "archive/writer.hpp"

#include "archive/reader.hpp"
#include "base/checked.hpp"

#include <algorithm>

namespace bale::archive {

namespace {

constexpr std::uint64_t maxDataPayload = 1 + maxDataDescriptorSize + maxChunkSize;

}

Result<WriteSummary> Writer::compact(File file, Reader& source, bool durable) {
    auto verified = source.verify(VerifyMode::Structure);
    if (!verified) {
        return std::unexpected(verified.error());
    }

    std::vector<bool> reachable(source.index_.size());
    std::size_t reachableCount = 0;
    for (const ChunkKey& key : source.manifest_.chunks) {
        const IndexEntry* entry = findChunk(source.index_, key);
        if (entry == nullptr) {
            return fail(ErrorKind::Malformed, "manifest references a missing chunk");
        }
        std::size_t position = static_cast<std::size_t>(entry - source.index_.data());
        if (!reachable[position]) {
            reachable[position] = true;
            ++reachableCount;
        }
    }

    std::size_t nameBytes = 0;
    std::uint64_t contentBytes = 0;
    for (const ManifestEntry& entry : source.manifest_.entries) {
        auto nextNameBytes = checkedAdd(nameBytes, entry.path.size());
        if (!nextNameBytes) {
            return fail(ErrorKind::LimitExceeded, "manifest names exceed the address space");
        }
        nameBytes = *nextNameBytes;
        nextNameBytes = checkedAdd(nameBytes, entry.target.size());
        if (!nextNameBytes) {
            return fail(ErrorKind::LimitExceeded, "manifest names exceed the address space");
        }
        nameBytes = *nextNameBytes;

        if (entry.kind == EntryKind::Regular) {
            auto nextContentBytes = checkedAdd(contentBytes, entry.length);
            if (!nextContentBytes) {
                return fail(ErrorKind::LimitExceeded, "snapshot content size overflows");
            }
            contentBytes = *nextContentBytes;
        }
    }

    WriterOptions options;
    options.archiveId = source.superblock_.archiveId;
    options.creationTimeNanoseconds = source.superblock_.creationTimeNs;
    options.comment = source.manifest_.comment;
    options.limits = source.options_.limits;
    options.durable = durable;
    options.compression.codec = CodecId::Raw;
    auto created = create(std::move(file), options);
    if (!created) {
        return std::unexpected(created.error());
    }
    Writer writer = std::move(*created);
    writer.inheritedWriter_ = source.manifest_.writer;
    writer.names_.reserve(nameBytes);
    writer.entries_.reserve(source.manifest_.entries.size());
    writer.chunks_.assign(source.manifest_.chunks.begin(), source.manifest_.chunks.end());
    writer.index_.reserve(reachableCount);
    writer.contentBytes_ = contentBytes;

    for (const ManifestEntry& entry : source.manifest_.entries) {
        auto pending = writer.beginEntry(entry.path, entry.kind);
        if (!pending) {
            return std::unexpected(pending.error());
        }

        auto target = writer.storeName(entry.target);
        (*pending)->targetOffset = target.offset;
        (*pending)->targetSize = target.size;
        (*pending)->length = entry.length;
        (*pending)->mtimeNanoseconds = entry.mtimeNanoseconds;
        (*pending)->mode = entry.mode;
        (*pending)->firstChunk = entry.firstChunk;
        (*pending)->chunkCount = entry.chunkCount;
    }

    RecordLimits limits{
        .maxPayloadLength = maxDataPayload,
        .maxDecodedLength = maxDataPayload,
    };
    for (std::uint32_t position : source.byOffset_) {
        if (!reachable[position]) {
            continue;
        }
        const IndexEntry& entry = source.index_[position];
        if (auto chunk = source.loadChunk(entry.key); !chunk) {
            return std::unexpected(chunk.error());
        }

        auto header = decodeRecordPrefix(
            std::span(source.buffer_).first(recordPrefixSize),
            limits,
            entry.recordOffset
        );
        if (!header) {
            return std::unexpected(header.error());
        }
        if (header->type != RecordType::Data || header->codec != entry.codec ||
            header->payloadLength + recordFramingSize != entry.recordLength) {
            return fail(ErrorKind::Malformed, "indexed chunk record changed during compaction");
        }
        if (header->flags != 0) {
            return fail(ErrorKind::Unsupported, "compaction cannot preserve chunk record flags");
        }

        auto payload =
            std::span<const std::byte>(source.buffer_)
                .subspan(recordPrefixSize, static_cast<std::size_t>(header->payloadLength));
        auto copied =
            writer.writeRecord(RecordType::Data, payload, {}, header->codec, header->decodedLength);
        if (!copied) {
            return std::unexpected(copied.error());
        }

        writer.index_.push_back(
            IndexEntry{
                .key = entry.key,
                .recordOffset = copied->offset,
                .recordLength = copied->length,
                .codec = entry.codec,
            }
        );
    }

    return writer.finish();
}

}
