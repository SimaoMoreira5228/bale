#include "archive/writer.hpp"

#include "archive/commit.hpp"
#include "archive/reader.hpp"
#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/envelope.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <random>
#include <utility>

namespace bale::archive {

namespace {

constexpr std::string_view writerName = "bale";
constexpr std::uint32_t maxReferences = std::numeric_limits<std::uint32_t>::max();

std::array<std::byte, 16> randomArchiveId() {
    std::random_device source;
    std::array<std::byte, 16> id{};
    for (std::size_t index = 0; index < id.size(); index += 4) {
        storeLe(id.data() + index, static_cast<std::uint32_t>(source()));
    }

    id[6] = (id[6] & std::byte{0x0F}) | std::byte{0x40};
    id[8] = (id[8] & std::byte{0x3F}) | std::byte{0x80};
    return id;
}

std::int64_t currentTimeNanoseconds() {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

Result<void> checkAttributes(const EntryAttributes& attributes) {
    if (attributes.mode && *attributes.mode > maxPermissionBits) {
        return fail(ErrorKind::Malformed, "mode has bits outside the permission bits");
    }
    return {};
}

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

Writer::Writer(File file, const WriterOptions& options) :
    file_(std::move(file)), options_(options), buffer_(options.chunkSize) {
}

Result<Writer> Writer::create(File file, const WriterOptions& options) {
    if (options.chunkSize < minChunkSize || options.chunkSize > maxChunkSize) {
        return fail(ErrorKind::LimitExceeded, "chunk size outside the supported range");
    }
    if (options.compression.codec != CodecId::Raw && options.compression.codec != CodecId::Zstd) {
        return fail(ErrorKind::Unsupported, "writer codec not supported");
    }

    Writer writer(std::move(file), options);
    if (options.compression.codec == CodecId::Zstd) {
        auto encoder = ZstdEncoder::create(options.compression.level);
        if (!encoder) {
            return std::unexpected(encoder.error());
        }
        writer.encoder_.emplace(std::move(*encoder));
        writer.compressionBuffer_.resize(ZstdEncoder::compressBound(options.chunkSize));
    }

    Superblock superblock;
    superblock.archiveId = options.archiveId ? *options.archiveId : randomArchiveId();
    superblock.creationTimeNs = options.creationTimeNanoseconds ? *options.creationTimeNanoseconds
                                                                : currentTimeNanoseconds();
    auto encoded = encodeSuperblock(superblock);
    auto written = writer.appendRaw(encoded);
    if (!written) {
        return std::unexpected(written.error());
    }
    return writer;
}

Result<Writer> Writer::append(File file, const WriterOptions& options) {
    if (options.chunkSize < minChunkSize || options.chunkSize > maxChunkSize) {
        return fail(ErrorKind::LimitExceeded, "chunk size outside the supported range");
    }
    if (options.compression.codec != CodecId::Raw && options.compression.codec != CodecId::Zstd) {
        return fail(ErrorKind::Unsupported, "writer codec not supported");
    }

    auto readFile = file.duplicate();
    if (!readFile) {
        return std::unexpected(readFile.error());
    }
    auto reader = Reader::open(std::move(*readFile));
    if (!reader) {
        return std::unexpected(reader.error());
    }
    auto verified = reader->verify(VerifyMode::Structure);
    if (!verified) {
        return std::unexpected(verified.error());
    }
    if (reader->commit().generation == std::numeric_limits<std::uint64_t>::max()) {
        return fail(ErrorKind::LimitExceeded, "archive generation limit exceeded");
    }

    std::uint64_t position = reader->footerOffset() + footerSize;
    auto truncated = file.truncate(position);
    if (!truncated) {
        return std::unexpected(truncated.error());
    }

    Writer writer(std::move(file), options);
    writer.position_ = position;
    writer.sequence_ = verified->records;
    writer.generation_ = reader->commit().generation + 1;
    writer.previousCommit_ = reader->commitDigest();
    writer.previousFooterOffset_ = reader->footerOffset();
    writer.index_.assign(reader->index().begin(), reader->index().end());
    for (std::uint32_t index = 0; index < writer.index_.size(); ++index) {
        writer.table_.insert(writer.index_, index);
    }

    if (options.compression.codec == CodecId::Zstd) {
        auto encoder = ZstdEncoder::create(options.compression.level);
        if (!encoder) {
            return std::unexpected(encoder.error());
        }
        writer.encoder_.emplace(std::move(*encoder));
        writer.compressionBuffer_.resize(ZstdEncoder::compressBound(options.chunkSize));
    }
    return writer;
}

Result<void> Writer::check() const {
    if (failure_) {
        return std::unexpected(*failure_);
    }
    if (finished_) {
        return fail(ErrorKind::Malformed, "archive already finished");
    }
    return {};
}

Result<void> Writer::poison(const Error& error) {
    failure_ = error;
    return std::unexpected(error);
}

Writer::NameRef Writer::storeName(std::string_view path) {
    NameRef name{
        .offset = names_.size(),
        .size = path.size(),
    };
    names_.append(path);
    return name;
}

std::string_view Writer::nameAt(std::size_t offset, std::size_t size) const {
    return std::string_view(names_).substr(offset, size);
}

Result<Writer::PendingEntry*> Writer::beginEntry(std::string_view path, EntryKind kind) {
    auto usable = check();
    if (!usable) {
        return std::unexpected(usable.error());
    }
    if (entries_.size() >= options_.limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "entry count limit exceeded");
    }

    auto valid = validateEntryPath(path, options_.limits, scratch_);
    if (!valid) {
        return std::unexpected(valid.error());
    }

    auto name = storeName(path);
    PendingEntry& entry = entries_.emplace_back();
    entry.pathOffset = name.offset;
    entry.pathSize = name.size;
    entry.kind = kind;
    entry.firstChunk = static_cast<std::uint32_t>(chunks_.size());
    return &entry;
}

Result<void> Writer::appendRaw(std::span<const std::byte> data) {
    auto end = checkedAdd<std::uint64_t>(position_, data.size());
    if (!end) {
        return poison(Error{.kind = ErrorKind::LimitExceeded, .what = "archive size overflows"});
    }

    auto written = file_.append(data);
    if (!written) {
        return poison(written.error());
    }
    position_ = *end;
    return {};
}

Result<Writer::RecordSpan> Writer::writeRecord(
    RecordType type,
    std::span<const std::byte> head,
    std::span<const std::byte> body,
    CodecId codec,
    std::uint64_t decodedLength
) {
    std::uint64_t payloadLength = std::uint64_t{head.size()} + body.size();
    RecordHeader header;
    header.type = type;
    header.payloadLength = payloadLength;
    header.decodedLength = decodedLength == 0 ? payloadLength : decodedLength;
    header.sequence = sequence_;
    header.codec = codec;

    Crc32c checksum;
    checksum.update(head);
    checksum.update(body);

    RecordSpan span{
        .offset = position_,
        .length = recordFramingSize + payloadLength,
    };
    auto prefix = encodeRecordPrefix(header);
    auto trailer = encodeRecordTrailer(checksum.value());
    for (auto part :
         {std::span<const std::byte>(prefix), head, body, std::span<const std::byte>(trailer)}) {
        auto written = appendRaw(part);
        if (!written) {
            return std::unexpected(written.error());
        }
    }

    ++sequence_;
    return span;
}

Result<void> Writer::storeChunk(std::span<const std::byte> chunk) {
    if (chunks_.size() >= maxReferences) {
        return poison(Error{.kind = ErrorKind::LimitExceeded, .what = "too many chunk references"});
    }

    auto key = chunkKeyOf(chunk);
    contentBytes_ += chunk.size();
    if (table_.find(index_, key) != nullptr) {
        chunks_.push_back(key);
        return {};
    }

    auto descriptor = encodeDataDescriptor(key, descriptor_);
    if (!descriptor) {
        return poison(descriptor.error());
    }
    std::span<const std::byte> storedChunk = chunk;
    CodecId codec = CodecId::Raw;
    if (encoder_) {
        auto compressed = encoder_->compress(chunk, compressionBuffer_);
        if (!compressed) {
            return poison(compressed.error());
        }
        if (*compressed < chunk.size()) {
            storedChunk = std::span(compressionBuffer_).first(*compressed);
            codec = CodecId::Zstd;
        }
    }

    auto span = writeRecord(
        RecordType::Data,
        descriptor_,
        storedChunk,
        codec,
        descriptor_.size() + chunk.size()
    );
    if (!span) {
        return std::unexpected(span.error());
    }

    index_.push_back(
        IndexEntry{
            .key = key,
            .recordOffset = span->offset,
            .recordLength = span->length,
            .codec = codec,
        }
    );
    table_.insert(index_, static_cast<std::uint32_t>(index_.size() - 1));
    chunks_.push_back(key);
    return {};
}

Result<void> Writer::addDirectory(std::string_view path, const EntryAttributes& attributes) {
    auto attributesValid = checkAttributes(attributes);
    if (!attributesValid) {
        return attributesValid;
    }

    auto entry = beginEntry(path, EntryKind::Directory);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    (*entry)->mtimeNanoseconds = attributes.mtimeNanoseconds;
    (*entry)->mode = attributes.mode;
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
        std::size_t filled = 0;
        while (filled < buffer_.size()) {
            auto count = source.readAt(length + filled, std::span(buffer_).subspan(filled));
            if (!count) {
                return poison(count.error());
            }
            if (*count == 0) {
                break;
            }
            filled += *count;
        }
        if (filled == 0) {
            break;
        }

        auto stored = storeChunk(std::span(buffer_).first(filled));
        if (!stored) {
            return stored;
        }
        length += filled;
        if (filled < buffer_.size()) {
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

    for (std::size_t at = 0; at < data.size(); at += buffer_.size()) {
        auto stored = storeChunk(data.subspan(at, std::min(buffer_.size(), data.size() - at)));
        if (!stored) {
            return stored;
        }
    }

    PendingEntry& stored = entries_[position];
    stored.length = data.size();
    stored.chunkCount = static_cast<std::uint32_t>(chunks_.size() - stored.firstChunk);
    stored.mtimeNanoseconds = attributes.mtimeNanoseconds;
    stored.mode = attributes.mode;
    return {};
}

Result<void> Writer::addSymlink(
    std::string_view path,
    std::string_view target,
    const EntryAttributes& attributes
) {
    if (target.empty() || target.size() > options_.limits.maxPathBytes ||
        target.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "symlink target empty, too long or containing NUL");
    }

    auto entry = beginEntry(path, EntryKind::Symlink);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    std::size_t position = entries_.size() - 1;

    auto name = storeName(target);
    entries_[position].targetOffset = name.offset;
    entries_[position].targetSize = name.size;
    entries_[position].mtimeNanoseconds = attributes.mtimeNanoseconds;
    return {};
}

Result<void> Writer::addHardLink(std::string_view path, std::string_view target) {
    auto valid = validateEntryPath(target, options_.limits, scratch_);
    if (!valid) {
        return valid;
    }

    auto entry = beginEntry(path, EntryKind::HardLink);
    if (!entry) {
        return std::unexpected(entry.error());
    }
    std::size_t position = entries_.size() - 1;

    auto name = storeName(target);
    entries_[position].targetOffset = name.offset;
    entries_[position].targetSize = name.size;
    return {};
}

Result<void> Writer::sortEntries() {
    std::ranges::sort(entries_, [this](const PendingEntry& left, const PendingEntry& right) {
        return nameAt(left.pathOffset, left.pathSize) < nameAt(right.pathOffset, right.pathSize);
    });

    auto duplicate = std::ranges::adjacent_find(
        entries_,
        [this](const PendingEntry& left, const PendingEntry& right) {
            return nameAt(left.pathOffset, left.pathSize) ==
                nameAt(right.pathOffset, right.pathSize);
        }
    );
    if (duplicate != entries_.end()) {
        return poison(Error{.kind = ErrorKind::Malformed, .what = "duplicate path in archive"});
    }
    return {};
}

Result<void> Writer::resolveHardLinks() {
    auto find = [this](std::string_view path) -> std::size_t {
        auto found =
            std::ranges::lower_bound(entries_, path, {}, [this](const PendingEntry& entry) {
                return nameAt(entry.pathOffset, entry.pathSize);
            });
        if (found == entries_.end() || nameAt(found->pathOffset, found->pathSize) != path) {
            return entries_.size();
        }
        return static_cast<std::size_t>(found - entries_.begin());
    };

    std::vector<std::size_t> groupRoot(entries_.size());
    std::vector<std::size_t> groupFirst(entries_.size());
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        groupRoot[index] = index;
        groupFirst[index] = index;
    }

    for (std::size_t index = 0; index < entries_.size(); ++index) {
        const PendingEntry& entry = entries_[index];
        if (entry.kind != EntryKind::HardLink) {
            continue;
        }
        std::size_t target = find(nameAt(entry.targetOffset, entry.targetSize));
        if (target == entries_.size() || entries_[target].kind != EntryKind::Regular) {
            return poison(
                Error{
                    .kind = ErrorKind::Malformed,
                    .what = "hard link target is not a regular entry"
                }
            );
        }
        groupRoot[index] = target;
        groupFirst[target] = std::min(groupFirst[target], index);
    }

    // NOTE: the format requires a hard link's target to precede it in byte order.
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        std::size_t root = groupRoot[index];
        std::size_t first = groupFirst[root];
        if (index != root && entries_[index].kind == EntryKind::HardLink) {
            entries_[index].targetOffset = entries_[first].pathOffset;
            entries_[index].targetSize = entries_[first].pathSize;
        }
        if (index != root || first == root) {
            continue;
        }

        PendingEntry& owner = entries_[first];
        PendingEntry& former = entries_[root];
        owner.kind = EntryKind::Regular;
        owner.targetOffset = 0;
        owner.targetSize = 0;
        owner.length = former.length;
        owner.firstChunk = former.firstChunk;
        owner.chunkCount = former.chunkCount;
        owner.mtimeNanoseconds = former.mtimeNanoseconds;
        owner.mode = former.mode;

        former.kind = EntryKind::HardLink;
        former.length = 0;
        former.chunkCount = 0;
        former.mtimeNanoseconds.reset();
        former.mode.reset();
        former.targetOffset = owner.pathOffset;
        former.targetSize = owner.pathSize;
    }
    return {};
}

Result<Writer::RecordSpan> Writer::writeManifest(Blake3Digest& digest) {
    Manifest manifest;
    manifest.entries.reserve(entries_.size());
    for (const auto& pending : entries_) {
        ManifestEntry& entry = manifest.entries.emplace_back();
        entry.path = nameAt(pending.pathOffset, pending.pathSize);
        entry.target = nameAt(pending.targetOffset, pending.targetSize);
        entry.length = pending.length;
        entry.mtimeNanoseconds = pending.mtimeNanoseconds;
        entry.mode = pending.mode;
        entry.firstChunk = pending.firstChunk;
        entry.chunkCount = pending.chunkCount;
        entry.kind = pending.kind;
    }
    manifest.chunks = std::move(chunks_);
    manifest.comment = options_.comment;
    manifest.writer = inheritedWriter_
        ? *inheritedWriter_
        : describeWriter(writerName, options_.compression, options_.chunkSize);

    auto encoded = encodeManifest(manifest, payload_);
    chunks_ = std::move(manifest.chunks);
    if (!encoded) {
        return std::unexpected(poison(encoded.error()).error());
    }

    Manifest decoded;
    auto valid = decodeManifest(payload_, 0, options_.limits, decoded);
    if (!valid) {
        return std::unexpected(poison(valid.error()).error());
    }

    digest = Blake3::of(HashDomain::Manifest, payload_);
    return writeRecord(RecordType::Manifest, payload_, {});
}

Result<Writer::RecordSpan> Writer::writeIndex(Blake3Digest& digest) {
    std::vector<IndexEntry> sorted = index_;
    std::ranges::sort(sorted, {}, &IndexEntry::key);

    auto encoded = encodeIndex(sorted, payload_);
    if (!encoded) {
        return std::unexpected(poison(encoded.error()).error());
    }

    digest = Blake3::of(HashDomain::Index, payload_);
    return writeRecord(RecordType::Index, payload_, {});
}

Result<WriteSummary> Writer::finish() {
    auto usable = check();
    if (!usable) {
        return std::unexpected(usable.error());
    }

    auto sorted = sortEntries();
    if (!sorted) {
        return std::unexpected(sorted.error());
    }
    auto linked = resolveHardLinks();
    if (!linked) {
        return std::unexpected(linked.error());
    }

    Commit commit;
    commit.generation = generation_;
    commit.previous = previousCommit_;
    commit.previousFooterOffset = previousFooterOffset_;
    auto manifest = writeManifest(commit.manifest.digest);
    if (!manifest) {
        return std::unexpected(manifest.error());
    }
    commit.manifest.offset = manifest->offset;
    commit.manifest.length = manifest->length;

    auto index = writeIndex(commit.index.digest);
    if (!index) {
        return std::unexpected(index.error());
    }
    commit.index.offset = index->offset;
    commit.index.length = index->length;

    auto encoded = encodeCommit(commit, payload_);
    if (!encoded) {
        return std::unexpected(poison(encoded.error()).error());
    }
    auto commitDigest = Blake3::of(HashDomain::Commit, payload_);
    auto record = writeRecord(RecordType::Commit, payload_, {});
    if (!record) {
        return std::unexpected(record.error());
    }

    if (options_.durable) {
        auto synced = file_.sync();
        if (!synced) {
            return std::unexpected(poison(synced.error()).error());
        }
    }

    Footer footer;
    footer.commitOffset = record->offset;
    footer.commitLength = record->length;
    footer.generation = commit.generation;
    footer.commitDigest = commitDigest;
    auto written = appendRaw(encodeFooter(footer));
    if (!written) {
        return std::unexpected(written.error());
    }

    if (options_.durable) {
        auto synced = file_.sync();
        if (!synced) {
            return std::unexpected(poison(synced.error()).error());
        }
    }

    finished_ = true;
    return WriteSummary{
        .entries = entries_.size(),
        .dataRecords = index_.size(),
        .chunkReferences = chunks_.size(),
        .contentBytes = contentBytes_,
        .archiveSize = position_,
    };
}

}
