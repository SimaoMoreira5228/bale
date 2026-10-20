#include "archive/writer.hpp"

#include "archive/chunk_pipeline.hpp"
#include "archive/commit.hpp"
#include "archive/encrypted.hpp"
#include "archive/reader.hpp"
#include "archive/signatures.hpp"
#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/envelope.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <random>
#include <thread>
#include <utility>

namespace bale::archive {

namespace {

constexpr std::string_view writerName = "bale";
constexpr std::uint32_t defaultWorkerCap = 8;
constexpr std::size_t outputBufferSize = std::size_t{256} * 1024;

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

std::span<const std::byte, 16> archiveIdSpan(const std::array<std::byte, 16>& id) {
    return std::span<const std::byte, 16>(id.data(), 16);
}

}

std::uint32_t defaultWorkers() {
    return std::clamp<std::uint32_t>(std::thread::hardware_concurrency(), 1, defaultWorkerCap);
}

Result<void> Writer::checkAttributes(const EntryAttributes& attributes) {
    if (attributes.mode && *attributes.mode > maxPermissionBits) {
        return fail(ErrorKind::Malformed, "mode has bits outside the permission bits");
    }
    return {};
}

Writer::Writer(File file, const WriterOptions& options) :
    file_(std::move(file)), options_(options) {
    output_.reserve(outputBufferSize);
}

Writer::Writer(Writer&& other) noexcept = default;

Writer& Writer::operator=(Writer&& other) noexcept = default;

Writer::~Writer() {
    if (pipeline_) {
        pipeline_->cancel();
    }
    if (!failure_ && !output_.empty()) {
        [[maybe_unused]] auto ignored = file_.append(output_);
    }
}

Result<void> Writer::checkOptions(const WriterOptions& options) {
    if (options.chunkPolicy == ChunkPolicy::Cdc) {
        auto valid = validateCdcParams(options.cdc);
        if (!valid) {
            return valid;
        }
    } else if (options.chunkSize < minChunkSize || options.chunkSize > maxChunkSize) {
        return fail(ErrorKind::LimitExceeded, "chunk size outside the supported range");
    }
    if (options.workers == 0 || options.workers > maxWorkers) {
        return fail(ErrorKind::LimitExceeded, "worker count outside the supported range");
    }
    return {};
}

Result<void> Writer::startPipeline() {
    std::uint32_t buffer =
        options_.chunkPolicy == ChunkPolicy::Cdc ? options_.cdc.max : options_.chunkSize;
    auto pipeline = ChunkPipeline::create(options_.compression, buffer, options_.workers);
    if (!pipeline) {
        return std::unexpected(pipeline.error());
    }
    pipeline_ = std::move(*pipeline);
    return {};
}

Result<Writer> Writer::create(File file, const WriterOptions& options) {
    auto valid = checkOptions(options);
    if (!valid) {
        return std::unexpected(valid.error());
    }
    if (options.experimentalEncryption) {
        return fail(
            ErrorKind::Malformed,
            "encrypted output requires createEncrypted with a password or recipient"
        );
    }

    Writer writer(std::move(file), options);
    auto started = writer.startPipeline();
    if (!started) {
        return std::unexpected(started.error());
    }

    Superblock superblock;
    superblock.archiveId = options.archiveId ? *options.archiveId : randomArchiveId();
    superblock.creationTimeNs = options.creationTimeNanoseconds ? *options.creationTimeNanoseconds
                                                                : currentTimeNanoseconds();
    writer.archiveId_ = superblock.archiveId;
    auto encoded = encodeSuperblock(superblock);
    auto written = writer.appendRaw(encoded);
    if (!written) {
        return std::unexpected(written.error());
    }
    return writer;
}

Result<Writer> Writer::append(File file, const WriterOptions& options) {
    auto valid = checkOptions(options);
    if (!valid) {
        return std::unexpected(valid.error());
    }
    if (options.experimentalEncryption) {
        return fail(
            ErrorKind::Malformed,
            "encrypted output requires appendEncrypted with a password or recipient"
        );
    }

    auto readFile = file.duplicate();
    if (!readFile) {
        return std::unexpected(readFile.error());
    }
    auto reader = Reader::open(std::move(*readFile));
    if (!reader) {
        return std::unexpected(reader.error());
    }
    if ((reader->superblock().requiredFeatures & encryptedRequiredFeature) != 0) {
        return fail(ErrorKind::PasswordRequired, "archive is encrypted");
    }
    auto verified = reader->verify(VerifyMode::Structure);
    if (!verified) {
        return std::unexpected(verified.error());
    }
    if (reader->commit().generation == std::numeric_limits<std::uint64_t>::max()) {
        return fail(ErrorKind::LimitExceeded, "archive generation limit exceeded");
    }

    Writer writer(std::move(file), options);
    auto started = writer.startPipeline();
    if (!started) {
        return std::unexpected(started.error());
    }

    std::uint64_t position = reader->footerOffset() + footerSize;
    auto truncated = writer.file_.truncate(position);
    if (!truncated) {
        return std::unexpected(truncated.error());
    }

    writer.position_ = position;
    writer.sequence_ = verified->records;
    writer.generation_ = reader->commit().generation + 1;
    writer.previousCommit_ = reader->commitDigest();
    writer.previousFooterOffset_ = reader->footerOffset();
    writer.archiveId_ = reader->superblock().archiveId;
    writer.index_.assign(reader->index().begin(), reader->index().end());
    for (std::uint32_t index = 0; index < writer.index_.size(); ++index) {
        writer.table_.insert(writer.index_, index);
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
    if (pipeline_) {
        pipeline_->cancel();
    }
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
    if (openFile_) {
        return fail(ErrorKind::Malformed, "previous file entry is still open");
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

    if (output_.size() + data.size() > outputBufferSize) {
        auto flushed = flushOutput();
        if (!flushed) {
            return flushed;
        }
    }
    if (data.size() >= outputBufferSize) {
        auto written = file_.append(data);
        if (!written) {
            return poison(written.error());
        }
    } else {
        output_.insert(output_.end(), data.begin(), data.end());
    }
    position_ = *end;
    return {};
}

Result<void> Writer::flushOutput() {
    if (output_.empty()) {
        return {};
    }
    auto written = file_.append(output_);
    output_.clear();
    if (!written) {
        return poison(written.error());
    }
    return {};
}

Result<Writer::RecordSpan> Writer::writeRecord(
    RecordType type,
    std::span<const std::byte> head,
    std::span<const std::byte> body,
    CodecId codec,
    std::uint64_t decodedLength,
    std::uint16_t flags
) {
    std::uint64_t payloadLength = std::uint64_t{head.size()} + body.size();
    RecordHeader header;
    header.type = type;
    header.flags = flags;
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
    if (encrypted_) {
        manifest.objectIds = std::move(objectIds_);
    }
    manifest.comment = options_.comment;
    std::uint32_t chunkSize =
        options_.chunkPolicy == ChunkPolicy::Cdc ? options_.cdc.target : options_.chunkSize;
    manifest.writer = inheritedWriter_ ? *inheritedWriter_
                                       : describeWriter(
                                             writerName,
                                             options_.compression,
                                             options_.chunkPolicy,
                                             chunkSize,
                                             options_.cdc,
                                             options_.workers
                                         );

    auto encoded = encodeManifest(manifest, payload_);
    chunks_ = std::move(manifest.chunks);
    if (encrypted_) {
        objectIds_ = std::move(manifest.objectIds);
    }
    if (!encoded) {
        return std::unexpected(poison(encoded.error()).error());
    }

    if (!encrypted_) {
        Manifest decoded;
        auto valid = decodeManifest(payload_, 0, options_.limits, decoded);
        if (!valid) {
            return std::unexpected(poison(valid.error()).error());
        }

        digest = Blake3::of(HashDomain::Manifest, payload_);
        return writeRecord(RecordType::Manifest, payload_, {});
    }

    std::vector<std::byte> plain(payload_.begin(), payload_.end());
    auto nonce = makeRecordNonce();
    if (!nonce) {
        return std::unexpected(poison(nonce.error()).error());
    }
    auto aad = manifestAad(archiveIdSpan(archiveId_), epoch_);
    auto sealed = crypto::seal(dataKey_.bytes(), *nonce, plain, aad);
    if (!sealed) {
        return std::unexpected(poison(sealed.error()).error());
    }
    payload_.clear();
    payload_.insert(payload_.end(), nonce->begin(), nonce->end());
    payload_.insert(payload_.end(), sealed->begin(), sealed->end());
    digest = Blake3::of(HashDomain::Manifest, payload_);
    return writeRecord(RecordType::Manifest, payload_, {}, CodecId::Raw, 0, encryptedRecordFlag);
}

Result<Writer::RecordSpan> Writer::writeIndex(Blake3Digest& digest) {
    std::vector<IndexEntry> sorted = index_;
    std::ranges::sort(sorted, {}, &IndexEntry::key);

    auto encoded = encodeIndex(sorted, payload_);
    if (!encoded) {
        return std::unexpected(poison(encoded.error()).error());
    }

    if (!encrypted_) {
        digest = Blake3::of(HashDomain::Index, payload_);
        return writeRecord(RecordType::Index, payload_, {});
    }
    std::vector<std::byte> plain(payload_.begin(), payload_.end());
    auto nonce = makeRecordNonce();
    if (!nonce) {
        return std::unexpected(poison(nonce.error()).error());
    }
    auto aad = indexAad(archiveIdSpan(archiveId_), epoch_);
    auto sealed = crypto::seal(dataKey_.bytes(), *nonce, plain, aad);
    if (!sealed) {
        return std::unexpected(poison(sealed.error()).error());
    }
    payload_.clear();
    payload_.insert(payload_.end(), nonce->begin(), nonce->end());
    payload_.insert(payload_.end(), sealed->begin(), sealed->end());
    digest = Blake3::of(HashDomain::Index, payload_);
    return writeRecord(RecordType::Index, payload_, {}, CodecId::Raw, 0, encryptedRecordFlag);
}

Result<void> Writer::addSignSeed(crypto::SecretBytes seed) {
    auto usable = check();
    if (!usable) {
        return usable;
    }
    if (seed.size() != crypto::signSeedSize) {
        return fail(ErrorKind::Malformed, "signing seed must hold 32 bytes", seed.size());
    }
    if (signSeeds_.size() >= maxSignaturesPerCommit) {
        return fail(ErrorKind::LimitExceeded, "too many signing keys", signSeeds_.size());
    }
    signSeeds_.push_back(std::move(seed));
    return {};
}

Result<void> Writer::writeSignatures(
    const Blake3Digest& commitDigest,
    std::uint64_t generation,
    std::uint64_t epoch
) {
    if (signSeeds_.size() > maxSignaturesPerCommit) {
        return fail(ErrorKind::LimitExceeded, "too many signing keys", signSeeds_.size());
    }
    std::span<const std::byte, 16> id(archiveId_.data(), 16);
    std::span<const std::byte, 32> digest(commitDigest.data(), 32);
    for (const auto& seed : signSeeds_) {
        if (seed.size() != crypto::signSeedSize) {
            return fail(ErrorKind::Malformed, "signing seed must hold 32 bytes", seed.size());
        }
        auto made = makeSignature(seed.bytes(), id, generation, epoch, digest);
        if (!made) {
            return std::unexpected(made.error());
        }
        std::vector<std::byte> payload;
        if (auto encoded = encodeSignature(*made, payload); !encoded) {
            return encoded;
        }
        auto record = writeRecord(
            RecordType::Extension,
            payload,
            {},
            CodecId::Raw,
            0,
            encrypted_ ? encryptedRecordFlag : 0
        );
        if (!record) {
            return std::unexpected(record.error());
        }
    }
    return {};
}

Result<WriteSummary> Writer::finish() {
    auto usable = check();
    if (!usable) {
        return std::unexpected(usable.error());
    }
    if (openFile_) {
        return fail(ErrorKind::Malformed, "file entry is still open");
    }
    auto drained = pump(true);
    if (!drained) {
        return std::unexpected(drained.error());
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
    if (encrypted_) {
        commit.requiredFeatures = encryptedCommitFeature;
        commit.epoch = epoch_;
    }
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
    if (!encrypted_) {
        auto commitDigest = Blake3::of(HashDomain::Commit, payload_);
        auto record = writeRecord(RecordType::Commit, payload_, {});
        if (!record) {
            return std::unexpected(record.error());
        }
        if (auto signed_ = writeSignatures(commitDigest, commit.generation, commit.epoch);
            !signed_) {
            return std::unexpected(poison(signed_.error()).error());
        }
        auto flushed = flushOutput();
        if (!flushed) {
            return std::unexpected(flushed.error());
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
        flushed = flushOutput();
        if (!flushed) {
            return std::unexpected(flushed.error());
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

    std::vector<std::byte> commitPlain(payload_.begin(), payload_.end());
    auto commitNonce = makeRecordNonce();
    if (!commitNonce) {
        return std::unexpected(poison(commitNonce.error()).error());
    }
    auto commitAadBytes = commitAad(archiveIdSpan(archiveId_), epoch_);
    auto commitSealed = crypto::seal(dataKey_.bytes(), *commitNonce, commitPlain, commitAadBytes);
    if (!commitSealed) {
        return std::unexpected(poison(commitSealed.error()).error());
    }
    payload_.clear();
    payload_.insert(payload_.end(), commitNonce->begin(), commitNonce->end());
    payload_.insert(payload_.end(), commitSealed->begin(), commitSealed->end());
    auto commitDigest = Blake3::of(HashDomain::Commit, payload_);
    auto commitRecord =
        writeRecord(RecordType::Commit, payload_, {}, CodecId::Raw, 0, encryptedRecordFlag);
    if (!commitRecord) {
        return std::unexpected(commitRecord.error());
    }
    if (auto signed_ = writeSignatures(commitDigest, commit.generation, commit.epoch); !signed_) {
        return std::unexpected(poison(signed_.error()).error());
    }
    auto flushed = flushOutput();
    if (!flushed) {
        return std::unexpected(flushed.error());
    }

    if (options_.durable) {
        auto synced = file_.sync();
        if (!synced) {
            return std::unexpected(poison(synced.error()).error());
        }
    }

    Footer footer;
    footer.commitOffset = commitRecord->offset;
    footer.commitLength = commitRecord->length;
    footer.generation = commit.generation;
    footer.commitDigest = commitDigest;
    auto written = appendRaw(encodeFooter(footer));
    if (!written) {
        return std::unexpected(written.error());
    }
    flushed = flushOutput();
    if (!flushed) {
        return std::unexpected(flushed.error());
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
