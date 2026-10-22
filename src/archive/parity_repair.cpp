#include "archive/parity_repair.hpp"

#include "archive/chunk.hpp"
#include "archive/chunk_codec.hpp"
#include "archive/commit.hpp"
#include "archive/encrypted.hpp"
#include "archive/index.hpp"
#include "archive/manifest.hpp"
#include "archive/parity_scan.hpp"
#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/blake3.hpp"
#include "checksum/crc.hpp"
#include "crypto/crypto.hpp"
#include "format/record.hpp"
#include "parity/reed_solomon.hpp"

#include <sodium/utils.h>

#include <algorithm>
#include <limits>
#include <set>

namespace bale::archive {

namespace {

constexpr std::uint64_t scanPayloadCap = (std::uint64_t{256} << 20) > maxEncryptedPayloadBytes
    ? (std::uint64_t{256} << 20)
    : maxEncryptedPayloadBytes;
constexpr std::uint64_t footerScanWindow = std::uint64_t{1} << 20;
constexpr std::size_t maxFooterCandidates = 64;
constexpr std::uint64_t repairMetaCap = std::uint64_t{256} << 20;
// NOTE: repaired bytes accumulate in a bounded journal and reach the file only
// NOTE: after every touched payload validates; a refusal discards the journal
// NOTE: so the archive is untouched, and re-running repair resumes from disk.
constexpr std::uint64_t maxRepairJournalBytes = std::uint64_t{64} << 20;

struct Extent {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
};

struct DataSpan {
    Extent payload;
    CodecId codec = CodecId::Raw;
    std::uint64_t recordOffset = 0;
    std::uint64_t recordLength = 0;
};

struct MetaSpan {
    Extent payload;
    std::uint64_t recordOffset = 0;
    std::uint64_t recordLength = 0;
    Blake3Digest digest{};
};

struct ParityRef {
    std::uint64_t recordOffset = 0;
    std::uint64_t recordLength = 0;
    Extent payload;
    ParityHeader header;
};

struct Segment {
    std::uint64_t fileOffset = 0;
    std::uint64_t length = 0;
    RecordType kind = RecordType::Data;
    CodecId codec = CodecId::Raw;
    std::uint64_t recordOffset = 0;
    std::uint64_t recordLength = 0;
};

void wipeBuffer(std::vector<std::byte>& bytes) {
    if (!bytes.empty()) {
        sodium_memzero(bytes.data(), bytes.size());
    }
}

Result<Extent> payloadExtent(std::uint64_t recordOffset, std::uint64_t recordLength) {
    if (recordLength < recordFramingSize) {
        return fail(ErrorKind::Malformed, "record shorter than framing", recordOffset);
    }
    auto payloadOffset = checkedAdd(recordOffset, static_cast<std::uint64_t>(recordPrefixSize));
    if (!payloadOffset) {
        return fail(ErrorKind::LimitExceeded, "record payload offset overflows", recordOffset);
    }
    return Extent{
        .offset = *payloadOffset,
        .length = recordLength - recordFramingSize,
    };
}

Result<std::vector<std::pair<Footer, std::uint64_t>>>
collectFooters(File& file, std::uint64_t fileSize) {
    std::vector<std::pair<Footer, std::uint64_t>> footers;
    if (fileSize < superblockSize + footerSize) {
        return footers;
    }
    std::uint64_t window = std::min(footerScanWindow, fileSize - superblockSize);
    std::uint64_t end = fileSize;
    std::uint64_t previousStart = fileSize;
    std::vector<std::byte> block;
    std::size_t attempts = 0;
    while (end > superblockSize) {
        std::uint64_t start = superblockSize;
        if (end - superblockSize > window) {
            start = end - window;
        }
        block.resize(static_cast<std::size_t>(end - start));
        if (auto read = file.readExactAt(start, block); !read) {
            return std::unexpected(read.error());
        }
        if (block.size() >= footerSize) {
            for (std::size_t at = block.size() - footerSize;; --at) {
                std::uint64_t candidateOffset = start + at;
                if (candidateOffset < previousStart) {
                    auto candidate = std::span(block).subspan(at, footerSize);
                    if (std::ranges::equal(candidate.first(footerMagic.size()), footerMagic)) {
                        if (auto decoded = decodeFooter(candidate, candidateOffset); decoded) {
                            footers.emplace_back(*decoded, candidateOffset);
                        }
                        ++attempts;
                        if (attempts == maxFooterCandidates) {
                            break;
                        }
                    }
                }
                if (at == 0 || attempts == maxFooterCandidates) {
                    break;
                }
            }
        }
        if (start == superblockSize || attempts == maxFooterCandidates) {
            break;
        }
        previousStart = start;
        end = start + footerSize - 1;
    }
    std::ranges::sort(footers, {}, [](const auto& entry) {
        return entry.second;
    });
    return footers;
}

Result<std::uint64_t>
findGenerationStart(File& file, const Footer& footer, std::uint64_t footerOffset) {
    if (footer.generation == 1) {
        return superblockSize;
    }
    if (footer.commitOffset <= superblockSize) {
        return fail(ErrorKind::Integrity, "generation has no room for a parent", footerOffset);
    }
    std::uint64_t window = std::min(footerScanWindow, footer.commitOffset - superblockSize);
    std::uint64_t end = footer.commitOffset;
    std::vector<std::byte> block;
    std::size_t attempts = 0;
    while (end > superblockSize) {
        std::uint64_t start = superblockSize;
        if (end - superblockSize > window) {
            start = end - window;
        }
        block.resize(static_cast<std::size_t>(end - start));
        if (auto read = file.readExactAt(start, block); !read) {
            return std::unexpected(read.error());
        }
        if (block.size() >= footerSize) {
            for (std::size_t at = block.size() - footerSize;; --at) {
                std::uint64_t candidateOffset = start + at;
                auto candidate = std::span(block).subspan(at, footerSize);
                if (std::ranges::equal(candidate.first(footerMagic.size()), footerMagic)) {
                    if (auto decoded = decodeFooter(candidate, candidateOffset);
                        decoded && decoded->generation + 1 == footer.generation) {
                        return candidateOffset + footerSize;
                    }
                    ++attempts;
                    if (attempts == maxFooterCandidates) {
                        return fail(
                            ErrorKind::Integrity,
                            "previous generation footer not found",
                            footerOffset
                        );
                    }
                }
                if (at == 0 || attempts == maxFooterCandidates) {
                    break;
                }
            }
        }
        if (start == superblockSize) {
            break;
        }
        end = start + footerSize - 1;
    }
    return fail(ErrorKind::Integrity, "previous generation footer not found", footerOffset);
}

class GenerationRepairer {
  public:
    GenerationRepairer(
        File& file,
        const Superblock& superblock,
        const Limits& limits,
        const RepairKeys* keys,
        Footer footer,
        std::uint64_t footerOffset
    ) :
        file_(file), limits_(limits), keys_(keys),
        encrypted_((superblock.requiredFeatures & encryptedRequiredFeature) != 0), footer_(footer),
        footerOffset_(footerOffset) {
        report_.generation = footer.generation;
    }

    Result<GenerationRepair> run() {
        report_.attempted = true;
        auto validated = validateDescriptor();
        if (!validated) {
            return note(validated.error());
        }
        auto start = findGenerationStart(file_, footer_, footerOffset_);
        if (!start) {
            return note(start.error());
        }
        genStart_ = *start;
        if (auto mapped = buildMap(); !mapped) {
            return note(mapped.error());
        }
        for (int pass = 0; pass < 2; ++pass) {
            buildSegments();
            if (auto checked = checkTotalLength(); !checked) {
                return note(checked.error());
            }
            if (auto repaired = repairStripes(); !repaired) {
                return std::unexpected(repaired.error());
            }
            if (commitTrusted_ || stopped_) {
                break;
            }
            if (auto overlaid = adoptRecoveredCommit(); !overlaid) {
                return note(overlaid.error());
            }
            if (!commitTrusted_) {
                break;
            }
        }
        if (!stopped_) {
            if (auto applied = applyJournal(); !applied) {
                return std::unexpected(applied.error());
            }
        }
        if (auto synced = file_.sync(); !synced) {
            return std::unexpected(synced.error());
        }
        return report_;
    }

  private:
    Result<GenerationRepair> note(const Error& error) {
        if (report_.note.empty()) {
            report_.note = std::string(error.what);
        }
        return report_;
    }

    struct JournalOp {
        std::uint64_t offset = 0;
        std::vector<std::byte> bytes;
    };

    Result<void> journalWrite(std::uint64_t offset, std::span<const std::byte> bytes) {
        auto end = checkedAdd(offset, static_cast<std::uint64_t>(bytes.size()));
        if (!end) {
            return fail(ErrorKind::LimitExceeded, "repair write offset overflows");
        }
        if (journalBytes_ + bytes.size() > maxRepairJournalBytes) {
            if (auto applied = applyJournal(); !applied) {
                return std::unexpected(applied.error());
            }
        }
        journal_.push_back(
            JournalOp{
                .offset = offset,
                .bytes = std::vector<std::byte>(bytes.begin(), bytes.end()),
            }
        );
        journalBytes_ += bytes.size();
        return {};
    }

    Result<bool> readThrough(std::uint64_t offset, std::span<std::byte> out) {
        if (auto read = file_.readExactAt(offset, out); !read) {
            if (read.error().kind == ErrorKind::Io) {
                return std::unexpected(read.error());
            }
            return false;
        }
        for (const auto& op : journal_) {
            std::uint64_t low = std::max(offset, op.offset);
            std::uint64_t high = std::min(offset + out.size(), op.offset + op.bytes.size());
            if (high > low) {
                std::ranges::copy(
                    std::span(op.bytes).subspan(
                        static_cast<std::size_t>(low - op.offset),
                        static_cast<std::size_t>(high - low)
                    ),
                    out.subspan(static_cast<std::size_t>(low - offset)).begin()
                );
            }
        }
        return true;
    }

    Result<void> applyJournal() {
        for (const auto& op : journal_) {
            if (auto wrote = file_.writeAt(op.offset, op.bytes); !wrote) {
                journal_.clear();
                journalBytes_ = 0;
                return std::unexpected(wrote.error());
            }
            report_.repaired = true;
        }
        journal_.clear();
        journalBytes_ = 0;
        return {};
    }

    Result<void> validateDescriptor() {
        const auto& descriptor = footer_.parity;
        if (descriptor.shardBytes > bale::parity::maxShardBytes) {
            return fail(ErrorKind::LimitExceeded, "parity shard size exceeds the supported range");
        }
        auto stripe = checkedMul(
            static_cast<std::uint64_t>(descriptor.dataShards) +
                static_cast<std::uint64_t>(descriptor.parityShards),
            static_cast<std::uint64_t>(descriptor.shardBytes)
        );
        if (!stripe || *stripe > maxParityStripeBytes) {
            return fail(ErrorKind::LimitExceeded, "parity stripe working set exceeds the budget");
        }
        auto size = fileSize();
        if (!size) {
            return std::unexpected(size.error());
        }
        if (descriptor.stripeCount > *size) {
            return fail(ErrorKind::Integrity, "parity stripe count exceeds the file size");
        }
        stripeBytes_ = static_cast<std::uint64_t>(descriptor.dataShards) * descriptor.shardBytes;
        return {};
    }

    Result<std::uint64_t> fileSize() {
        if (!cachedSize_) {
            auto size = file_.size();
            if (!size) {
                return std::unexpected(size.error());
            }
            cachedSize_ = *size;
        }
        return *cachedSize_;
    }

    Result<void> buildMap() {
        auto scan = scanGeneration(file_, genStart_, footerOffset_, scanPayloadCap);
        if (!scan) {
            return std::unexpected(scan.error());
        }
        scan_ = std::move(*scan);
        for (const auto& record : scan_.records) {
            if (record.type == RecordType::Parity) {
                if (!collectParityRef(record)) {
                    orphans_.insert(record.offset);
                }
                continue;
            }
            if (record.type == RecordType::Data) {
                auto payload = payloadExtent(record.offset, record.length);
                if (!payload) {
                    return std::unexpected(payload.error());
                }
                data_.push_back(
                    DataSpan{
                        .payload = *payload,
                        .codec = record.codec,
                        .recordOffset = record.offset,
                        .recordLength = record.length,
                    }
                );
                continue;
            }
            if (record.type == RecordType::Extension && record.hasExtensionKind &&
                record.extensionKind == keyslotExtensionKind) {
                auto payload = payloadExtent(record.offset, record.length);
                if (!payload) {
                    return std::unexpected(payload.error());
                }
                keyslots_.push_back(*payload);
            }
        }
        if (encrypted_ && keys_ == nullptr) {
            return fail(
                ErrorKind::PasswordRequired,
                "parity repair of an encrypted generation needs keys"
            );
        }
        mapCommitSpan();
        return adoptCommit();
    }

    void mapCommitSpan() {
        std::array<std::byte, recordPrefixSize> prefix{};
        if (!file_.readExactAt(footer_.commitOffset, prefix)) {
            return;
        }
        RecordLimits limits{
            .maxPayloadLength = encrypted_ ? maxEncryptedPayloadBytes : 4096,
            .maxDecodedLength = encrypted_ ? maxEncryptedPayloadBytes : 4096,
        };
        auto header = decodeRecordPrefix(prefix, limits, footer_.commitOffset);
        if (!header || header->type != RecordType::Commit) {
            return;
        }
        auto size = recordSize(header->payloadLength);
        if (!size || *size != footer_.commitLength) {
            return;
        }
        std::vector<std::byte> bytes(static_cast<std::size_t>(*size));
        if (!file_.readExactAt(footer_.commitOffset, bytes)) {
            return;
        }
        if (!decodeRecord(bytes, limits, footer_.commitOffset)) {
            return;
        }
        auto payload = payloadExtent(footer_.commitOffset, footer_.commitLength);
        if (!payload) {
            return;
        }
        commitSpan_ = MetaSpan{
            .payload = *payload,
            .recordOffset = footer_.commitOffset,
            .recordLength = footer_.commitLength,
            .digest = footer_.commitDigest,
        };
    }

    [[nodiscard]] bool collectParityRef(const ScannedRecord& record) {
        std::uint16_t wantFlags = parityRecordFlag;
        if (encrypted_) {
            wantFlags |= encryptedRecordFlag;
        }
        if (record.flags != wantFlags) {
            return false;
        }
        RecordLimits limits{
            .maxPayloadLength = maxParityRecordPayload,
            .maxDecodedLength = maxParityRecordPayload,
        };
        std::vector<std::byte> bytes(static_cast<std::size_t>(record.length));
        if (!file_.readExactAt(record.offset, bytes)) {
            return false;
        }
        auto decoded = decodeRecord(bytes, limits, record.offset);
        if (!decoded) {
            return false;
        }
        auto parsed = decodeParityRecord(decoded->payload, record.offset + recordPrefixSize);
        if (!parsed) {
            return false;
        }
        const auto& descriptor = footer_.parity;
        if (parsed->groupId != descriptor.groupId || parsed->generation != footer_.generation ||
            parsed->dataShards != descriptor.dataShards ||
            parsed->parityShards != descriptor.parityShards ||
            parsed->shardBytes != descriptor.shardBytes ||
            parsed->stripeCount != descriptor.stripeCount) {
            return false;
        }
        auto payload = payloadExtent(record.offset, record.length);
        if (!payload) {
            return false;
        }
        std::uint64_t headerLength =
            parityHeaderLength(descriptor.dataShards + descriptor.parityShards);
        if (payload->length < headerLength + descriptor.shardBytes) {
            return false;
        }
        auto shardOffset = checkedAdd(payload->offset, headerLength);
        if (!shardOffset) {
            return false;
        }
        parityRefs_.push_back(
            ParityRef{
                .recordOffset = record.offset,
                .recordLength = record.length,
                .payload =
                    Extent{
                        .offset = *shardOffset,
                        .length = descriptor.shardBytes,
                    },
                .header = *parsed,
            }
        );
        return true;
    }

    Result<void> adoptCommit() {
        if (!commitSpan_) {
            return {};
        }
        RecordLimits commitLimits{
            .maxPayloadLength = encrypted_ ? maxEncryptedPayloadBytes : 4096,
            .maxDecodedLength = encrypted_ ? maxEncryptedPayloadBytes : 4096,
        };
        std::vector<std::byte> bytes(static_cast<std::size_t>(footer_.commitLength));
        if (auto read = file_.readExactAt(footer_.commitOffset, bytes); !read) {
            return std::unexpected(read.error());
        }
        auto decoded = decodeRecord(bytes, commitLimits, footer_.commitOffset);
        if (!decoded) {
            return {};
        }
        std::uint16_t wantFlags = encrypted_ ? encryptedRecordFlag : 0;
        if (decoded->header.flags != wantFlags || decoded->header.codec != CodecId::Raw) {
            return {};
        }
        if (Blake3::of(HashDomain::Commit, decoded->payload) != footer_.commitDigest) {
            return {};
        }
        if (!encrypted_) {
            auto commit = decodeCommit(decoded->payload, footer_.commitOffset + recordPrefixSize);
            if (!commit || commit->generation != footer_.generation ||
                (commit->requiredFeatures & parityCommitFeature) == 0) {
                return {};
            }
            return adoptOverlay(*commit);
        }
        for (const auto& [epoch, key] : keys_->byEpoch) {
            if (decoded->payload.size() < crypto::nonceSize + crypto::tagSize) {
                break;
            }
            std::span<const std::byte, 16> id(keys_->archiveId.data(), 16);
            auto aad = commitAad(id, epoch);
            auto opened = crypto::open(
                key.bytes(),
                decoded->payload.first(crypto::nonceSize),
                decoded->payload.subspan(crypto::nonceSize),
                aad
            );
            if (!opened) {
                if (opened.error().kind != ErrorKind::Integrity) {
                    return std::unexpected(opened.error());
                }
                continue;
            }
            auto commit = decodeCommit(*opened, footer_.commitOffset + recordPrefixSize);
            bool usable = commit && commit->generation == footer_.generation &&
                (commit->requiredFeatures & parityCommitFeature) != 0 && commit->epoch == epoch;
            wipeBuffer(*opened);
            if (!usable) {
                continue;
            }
            return adoptOverlay(*commit);
        }
        return {};
    }

    Result<void> adoptOverlay(const Commit& commit) {
        if (!commitSpan_) {
            return fail(ErrorKind::Integrity, "commit span missing for overlay");
        }
        Extent commitPayload = commitSpan_->payload;
        for (const RecordReference* reference : {&commit.manifest, &commit.index}) {
            if (reference->offset < genStart_ ||
                !fitsWithin(reference->offset, reference->length, footer_.commitOffset) ||
                reference->length < recordFramingSize) {
                return fail(
                    ErrorKind::Integrity,
                    "commit metadata reference outside its generation"
                );
            }
        }
        if (commit.manifest.offset < commit.index.offset + commit.index.length &&
            commit.index.offset < commit.manifest.offset + commit.manifest.length) {
            return fail(ErrorKind::Integrity, "commit metadata records overlap");
        }
        RecordLimits metaLimits{
            .maxPayloadLength = repairMetaCap,
            .maxDecodedLength = repairMetaCap,
        };
        auto readMeta = [&](const RecordReference& reference,
                            RecordType type,
                            std::vector<std::byte>& bytes) -> Result<Record> {
            bytes.resize(static_cast<std::size_t>(reference.length));
            if (auto read = file_.readExactAt(reference.offset, bytes); !read) {
                return std::unexpected(read.error());
            }
            auto record = decodeRecord(bytes, metaLimits, reference.offset);
            if (!record || record->header.type != type) {
                return fail(ErrorKind::Integrity, "metadata record failed validation");
            }
            return *record;
        };
        auto indexRecord = readMeta(commit.index, RecordType::Index, indexBytes_);
        if (!indexRecord) {
            return {};
        }
        auto manifestRecord = readMeta(commit.manifest, RecordType::Manifest, manifestBytes_);
        if (!manifestRecord) {
            return {};
        }
        std::span<const std::byte> indexPayload = indexRecord->payload;
        std::span<const std::byte> manifestPayload = manifestRecord->payload;
        std::vector<std::byte> plainIndex;
        std::vector<std::byte> plainManifest;
        if (encrypted_) {
            auto key = keys_->byEpoch.find(commit.epoch);
            if (key == keys_->byEpoch.end()) {
                return {};
            }
            std::span<const std::byte, 16> id(keys_->archiveId.data(), 16);
            auto openMeta = [&](std::span<const std::byte> payload,
                                const std::vector<std::byte>& aad,
                                std::vector<std::byte>& plain) -> Result<void> {
                if (payload.size() < crypto::nonceSize + crypto::tagSize) {
                    return fail(ErrorKind::Integrity, "encrypted metadata too short");
                }
                auto opened = crypto::open(
                    key->second.bytes(),
                    payload.first(crypto::nonceSize),
                    payload.subspan(crypto::nonceSize),
                    aad
                );
                if (!opened) {
                    return std::unexpected(opened.error());
                }
                plain.assign(opened->begin(), opened->end());
                wipeBuffer(*opened);
                return {};
            };
            if (auto opened = openMeta(indexPayload, indexAad(id, commit.epoch), plainIndex);
                !opened) {
                if (opened.error().kind == ErrorKind::Integrity) {
                    return {};
                }
                return std::unexpected(opened.error());
            }
            if (auto opened =
                    openMeta(manifestPayload, manifestAad(id, commit.epoch), plainManifest);
                !opened) {
                if (opened.error().kind == ErrorKind::Integrity) {
                    return {};
                }
                return std::unexpected(opened.error());
            }
            indexPayload = plainIndex;
            manifestPayload = plainManifest;
        }
        if (Blake3::of(HashDomain::Index, indexRecord->payload) != commit.index.digest ||
            Blake3::of(HashDomain::Manifest, manifestRecord->payload) != commit.manifest.digest) {
            return {};
        }
        std::vector<IndexEntry> entries;
        if (!decodeIndex(
                indexPayload,
                commit.index.offset + recordPrefixSize,
                std::numeric_limits<std::uint32_t>::max(),
                entries
            )) {
            return {};
        }
        Manifest manifest;
        if (!decodeManifest(
                manifestPayload,
                commit.manifest.offset + recordPrefixSize,
                limits_,
                manifest
            )) {
            return {};
        }
        if (encrypted_ && manifest.objectIds.size() != manifest.chunks.size()) {
            return {};
        }
        auto indexPayloadExtent = payloadExtent(commit.index.offset, commit.index.length);
        auto manifestPayloadExtent = payloadExtent(commit.manifest.offset, commit.manifest.length);
        if (!indexPayloadExtent || !manifestPayloadExtent) {
            return fail(ErrorKind::Integrity, "commit metadata shorter than framing");
        }
        commit_ = commit;
        commitTrusted_ = true;
        indexEntries_ = std::move(entries);
        manifest_ = std::move(manifest);
        index_ = MetaSpan{
            .payload = *indexPayloadExtent,
            .recordOffset = commit.index.offset,
            .recordLength = commit.index.length,
            .digest = commit.index.digest,
        };
        manifestSpan_ = MetaSpan{
            .payload = *manifestPayloadExtent,
            .recordOffset = commit.manifest.offset,
            .recordLength = commit.manifest.length,
            .digest = commit.manifest.digest,
        };
        commitSpan_ = MetaSpan{
            .payload = commitPayload,
            .recordOffset = footer_.commitOffset,
            .recordLength = footer_.commitLength,
            .digest = footer_.commitDigest,
        };
        manifestBytes_.clear();
        manifestBytes_.shrink_to_fit();
        return overlayDataSpans();
    }

    Result<void> overlayDataSpans() {
        std::vector<DataSpan> overlaid;
        overlaid.reserve(indexEntries_.size());
        for (const auto& entry : indexEntries_) {
            if (entry.recordOffset < genStart_ ||
                !fitsWithin(entry.recordOffset, entry.recordLength, footer_.commitOffset)) {
                return fail(ErrorKind::Integrity, "index record outside its generation");
            }
            auto payload = payloadExtent(entry.recordOffset, entry.recordLength);
            if (!payload) {
                return fail(ErrorKind::Integrity, "indexed record shorter than framing");
            }
            overlaid.push_back(
                DataSpan{
                    .payload = *payload,
                    .codec = entry.codec,
                    .recordOffset = entry.recordOffset,
                    .recordLength = entry.recordLength,
                }
            );
        }
        std::ranges::sort(overlaid, {}, [](const DataSpan& span) {
            return span.recordOffset;
        });
        for (const auto& walked : data_) {
            bool found = false;
            for (const auto& span : overlaid) {
                if (span.recordOffset == walked.recordOffset) {
                    if (span.recordLength != walked.recordLength || span.codec != walked.codec) {
                        return fail(ErrorKind::Integrity, "index disagrees with the record stream");
                    }
                    found = true;
                    break;
                }
            }
            if (!found && !scan_.truncated) {
                return fail(ErrorKind::Integrity, "record stream disagrees with the index");
            }
        }
        data_ = std::move(overlaid);
        return {};
    }

    void buildSegments() {
        segments_.clear();
        for (const auto& span : data_) {
            segments_.push_back(
                Segment{
                    .fileOffset = span.payload.offset,
                    .length = span.payload.length,
                    .kind = RecordType::Data,
                    .codec = span.codec,
                    .recordOffset = span.recordOffset,
                    .recordLength = span.recordLength,
                }
            );
        }
        // NOTE: without a trusted commit the index, manifest, commit and keyslot
        // NOTE: stream positions are unknowable, so only the leading data prefix
        // NOTE: is addressable. The commit file range stays known separately for
        // NOTE: the recovery pass.
        if (commitTrusted_) {
            if (index_) {
                segments_.push_back(
                    Segment{
                        .fileOffset = index_->payload.offset,
                        .length = index_->payload.length,
                        .kind = RecordType::Index,
                        .recordOffset = index_->recordOffset,
                        .recordLength = index_->recordLength,
                    }
                );
            }
            if (manifestSpan_) {
                segments_.push_back(
                    Segment{
                        .fileOffset = manifestSpan_->payload.offset,
                        .length = manifestSpan_->payload.length,
                        .kind = RecordType::Manifest,
                        .recordOffset = manifestSpan_->recordOffset,
                        .recordLength = manifestSpan_->recordLength,
                    }
                );
            }
            if (commitSpan_) {
                segments_.push_back(
                    Segment{
                        .fileOffset = commitSpan_->payload.offset,
                        .length = commitSpan_->payload.length,
                        .kind = RecordType::Commit,
                        .recordOffset = commitSpan_->recordOffset,
                        .recordLength = commitSpan_->recordLength,
                    }
                );
            }
            for (const auto& keyslot : keyslots_) {
                segments_.push_back(
                    Segment{
                        .fileOffset = keyslot.offset,
                        .length = keyslot.length,
                        .kind = RecordType::Extension,
                    }
                );
            }
        }
        streamLength_ = 0;
        for (const auto& segment : segments_) {
            streamLength_ += segment.length;
        }
        mappedPrefix_ = streamLength_;
    }

    Result<void> checkTotalLength() {
        if (!commitTrusted_) {
            return {};
        }
        auto stripes =
            stripeCountFor(streamLength_, footer_.parity.dataShards, footer_.parity.shardBytes);
        if (!stripes) {
            return std::unexpected(stripes.error());
        }
        if (*stripes != footer_.parity.stripeCount) {
            return fail(ErrorKind::Integrity, "stripe stream length disagrees with its footer");
        }
        std::vector<ParityRef> matching;
        for (const auto& ref : parityRefs_) {
            if (ref.header.streamLength == streamLength_) {
                matching.push_back(ref);
            }
        }
        parityRefs_ = std::move(matching);
        return {};
    }

    Result<void> repairStripes() {
        const auto& descriptor = footer_.parity;
        auto coder = parity::ReedSolomon::make(descriptor.dataShards, descriptor.parityShards);
        if (!coder) {
            return std::unexpected(coder.error());
        }
        auto scratchSize =
            parity::ReedSolomon::scratchBytes(descriptor.dataShards, descriptor.parityShards);
        if (!scratchSize) {
            return std::unexpected(scratchSize.error());
        }
        std::vector<std::byte> scratch(*scratchSize);
        std::uint32_t total = descriptor.dataShards + descriptor.parityShards;
        std::vector<std::vector<std::byte>> shards(
            total,
            std::vector<std::byte>(descriptor.shardBytes)
        );
        std::vector<std::span<std::byte>> shardViews(total);
        for (std::uint32_t shard = 0; shard < total; ++shard) {
            shardViews[shard] = shards[shard];
        }
        std::vector<std::uint32_t> missing;
        std::vector<std::byte> recordBuffer;
        ChunkDecoder decoder;
        std::uint64_t processed = 0;

        for (std::uint64_t stripe = 0; stripe < descriptor.stripeCount; ++stripe) {
            auto stripeStart = checkedMul(stripe, stripeBytes_);
            if (!stripeStart || *stripeStart >= mappedPrefix_) {
                break;
            }
            ++processed;
            auto gated = gateStripe(stripe, *stripeStart, shards, missing, recordBuffer);
            if (!gated) {
                return stop(gated.error());
            }
            if (missing.empty()) {
                continue;
            }
            if (missing.size() > descriptor.parityShards) {
                report_.note = "erasures exceed the parity budget";
                stopped_ = true;
                break;
            }
            for (std::uint32_t shard : missing) {
                std::ranges::fill(shards[shard], std::byte{0});
            }
            if (auto repaired = coder->repair(shardViews, missing, scratch); !repaired) {
                return stop(repaired.error());
            }
            if (auto verified = verifyStripe(stripe, shards, missing); !verified) {
                return stop(verified.error());
            }
            if (auto written = writeStripe(stripe, *stripeStart, shards, missing); !written) {
                return std::unexpected(written.error());
            }
            auto stripeEnd = checkedAdd(*stripeStart, stripeBytes_);
            if (!stripeEnd) {
                return stop(
                    Error{
                        .kind = ErrorKind::LimitExceeded,
                        .what = "parity stripe offset overflows",
                    }
                );
            }
            if (auto validated = validateCompletedPayloads(*stripeEnd, decoder, recordBuffer);
                !validated) {
                return stop(validated.error());
            }
        }
        if (processed == 0 && report_.note.empty()) {
            report_.note = "no stripe fully mapped";
            stopped_ = true;
        }
        return {};
    }

    Result<void> stop(const Error& error) {
        if (error.kind == ErrorKind::Io) {
            return std::unexpected(error);
        }
        if (report_.note.empty()) {
            report_.note = std::string(error.what);
        }
        stopped_ = true;
        return {};
    }

    Result<void> gateStripe(
        std::uint64_t stripe,
        std::uint64_t stripeStart,
        std::vector<std::vector<std::byte>>& shards,
        std::vector<std::uint32_t>& missing,
        std::vector<std::byte>& recordBuffer
    ) {
        missing.clear();
        const auto& descriptor = footer_.parity;
        std::uint32_t total = descriptor.dataShards + descriptor.parityShards;
        std::vector<const ParityRef*> refs;
        for (const auto& ref : parityRefs_) {
            if (ref.header.stripeIndex == stripe) {
                refs.push_back(&ref);
            }
        }
        std::vector<std::uint32_t> table;
        bool hasTable = false;
        for (const auto* ref : refs) {
            if (!hasTable) {
                table = ref->header.crc;
                hasTable = true;
            } else if (table != ref->header.crc) {
                return fail(ErrorKind::Integrity, "parity records disagree on a stripe table");
            }
        }
        if (hasTable && table.size() != total) {
            return fail(ErrorKind::Integrity, "stripe table does not cover every shard");
        }
        for (std::uint32_t shard = 0; shard < descriptor.dataShards; ++shard) {
            auto shardOffset =
                checkedAdd(stripeStart, static_cast<std::uint64_t>(shard) * descriptor.shardBytes);
            if (!shardOffset) {
                return fail(ErrorKind::LimitExceeded, "parity shard offset overflows");
            }
            auto shardRead = readStripeShard(*shardOffset, shards[shard]);
            if (!shardRead) {
                return std::unexpected(shardRead.error());
            }
            if (!*shardRead) {
                missing.push_back(shard);
                continue;
            }
            bool present = false;
            if (hasTable) {
                present = Crc32c::of(shards[shard]) == table[shard];
            } else {
                auto gated = recordGate(*shardOffset, recordBuffer);
                if (!gated) {
                    return std::unexpected(gated.error());
                }
                present = *gated;
            }
            if (!present) {
                missing.push_back(shard);
            }
        }
        for (std::uint32_t parity = 0; parity < descriptor.parityShards; ++parity) {
            std::uint32_t shard = descriptor.dataShards + parity;
            const ParityRef* found = nullptr;
            for (const auto* ref : refs) {
                if (ref->header.shardIndex == shard) {
                    found = ref;
                    break;
                }
            }
            if (found == nullptr) {
                missing.push_back(shard);
                continue;
            }
            auto present = readThrough(found->payload.offset, shards[shard]);
            if (!present) {
                return std::unexpected(present.error());
            }
            if (!*present) {
                missing.push_back(shard);
                continue;
            }
            if (hasTable && Crc32c::of(shards[shard]) != table[shard]) {
                missing.push_back(shard);
            }
        }
        return {};
    }

    Result<bool> readStripeShard(std::uint64_t streamOffset, std::span<std::byte> out) {
        std::uint64_t readable = streamLength_ > streamOffset ? streamLength_ - streamOffset : 0;
        if (readable > out.size()) {
            readable = out.size();
        }
        std::fill(out.begin() + static_cast<std::ptrdiff_t>(readable), out.end(), std::byte{0});
        std::uint64_t position = 0;
        std::size_t filled = 0;
        std::size_t want = static_cast<std::size_t>(readable);
        for (const auto& segment : segments_) {
            if (filled == want) {
                break;
            }
            auto segmentEnd = checkedAdd(position, segment.length);
            if (!segmentEnd) {
                return fail(ErrorKind::LimitExceeded, "parity stream range overflows");
            }
            if (streamOffset >= *segmentEnd) {
                position = *segmentEnd;
                continue;
            }
            std::uint64_t skip = streamOffset > position ? streamOffset - position : 0;
            std::size_t take = static_cast<std::size_t>(
                std::min(segment.length - skip, static_cast<std::uint64_t>(want - filled))
            );
            auto rangeStart = checkedAdd(segment.fileOffset, skip);
            if (!rangeStart) {
                return fail(ErrorKind::LimitExceeded, "parity stream range overflows");
            }
            auto chunk = readThrough(*rangeStart, out.subspan(filled, take));
            if (!chunk) {
                return std::unexpected(chunk.error());
            }
            if (!*chunk) {
                return false;
            }
            filled += take;
            position = *segmentEnd;
        }
        return filled == want;
    }

    Result<bool> recordGate(std::uint64_t streamOffset, std::vector<std::byte>& recordBuffer) {
        const Segment* owner = segmentAt(streamOffset);
        if (owner == nullptr || owner->recordLength < recordFramingSize) {
            return false;
        }
        std::uint64_t payloadLength = owner->recordLength - recordFramingSize;
        if (payloadLength > repairMetaCap) {
            return false;
        }
        recordBuffer.resize(static_cast<std::size_t>(owner->recordLength));
        auto recordRead = readThrough(owner->recordOffset, recordBuffer);
        if (!recordRead) {
            return std::unexpected(recordRead.error());
        }
        if (!*recordRead) {
            return false;
        }
        std::span<const std::byte> payload =
            std::span(recordBuffer)
                .subspan(recordPrefixSize, static_cast<std::size_t>(payloadLength));
        std::span<const std::byte> trailer =
            std::span(recordBuffer)
                .subspan(
                    recordPrefixSize + static_cast<std::size_t>(payloadLength),
                    recordTrailerSize
                );
        return verifyRecordTrailer(payload, trailer, owner->recordOffset + recordPrefixSize)
            .has_value();
    }

    [[nodiscard]] const Segment* segmentAt(std::uint64_t streamOffset) const {
        std::uint64_t position = 0;
        for (const auto& segment : segments_) {
            if (streamOffset >= position && streamOffset < position + segment.length) {
                return &segment;
            }
            position += segment.length;
        }
        return nullptr;
    }

    Result<void> verifyStripe(
        std::uint64_t stripe,
        std::vector<std::vector<std::byte>>& shards,
        std::span<const std::uint32_t> missing
    ) {
        const auto& descriptor = footer_.parity;
        std::uint32_t total = descriptor.dataShards + descriptor.parityShards;
        const std::vector<std::uint32_t>* table = nullptr;
        for (const auto& ref : parityRefs_) {
            if (ref.header.stripeIndex == stripe) {
                if (table == nullptr) {
                    table = &ref.header.crc;
                } else if (*table != ref.header.crc) {
                    return fail(ErrorKind::Integrity, "parity records disagree on a stripe table");
                }
            }
        }
        auto isMissing = [&](std::uint32_t shard) {
            return std::ranges::find(missing, shard) != missing.end();
        };
        if (table != nullptr) {
            if (table->size() != total) {
                return fail(ErrorKind::Integrity, "stripe table does not cover every shard");
            }
            for (std::uint32_t shard = 0; shard < total; ++shard) {
                if (!isMissing(shard)) {
                    continue;
                }
                if (shard < descriptor.dataShards || hasParityRef(stripe, shard)) {
                    if (Crc32c::of(std::span<const std::byte>(shards[shard])) != (*table)[shard]) {
                        return fail(ErrorKind::Integrity, "repaired stripe fails its crc table");
                    }
                }
            }
        }
        return {};
    }

    [[nodiscard]] bool hasParityRef(std::uint64_t stripe, std::uint32_t shard) const {
        for (const auto& ref : parityRefs_) {
            if (ref.header.stripeIndex == stripe && ref.header.shardIndex == shard) {
                return true;
            }
        }
        return false;
    }

    Result<void> writeStripe(
        std::uint64_t stripe,
        std::uint64_t stripeStart,
        std::vector<std::vector<std::byte>>& shards,
        std::span<const std::uint32_t> missing
    ) {
        const auto& descriptor = footer_.parity;
        for (std::uint32_t shard : missing) {
            if (shard >= descriptor.dataShards) {
                continue;
            }
            auto shardOffset =
                checkedAdd(stripeStart, static_cast<std::uint64_t>(shard) * descriptor.shardBytes);
            if (!shardOffset) {
                return fail(ErrorKind::LimitExceeded, "parity shard offset overflows");
            }
            auto scattered = scatterShard(*shardOffset, shards[shard]);
            if (!scattered) {
                return std::unexpected(scattered.error());
            }
            if (!*scattered) {
                return fail(ErrorKind::Integrity, "repaired shard has nowhere to go");
            }
        }
        for (std::uint32_t shard : missing) {
            if (shard < descriptor.dataShards) {
                continue;
            }
            const ParityRef* found = nullptr;
            for (const auto& ref : parityRefs_) {
                if (ref.header.stripeIndex == stripe && ref.header.shardIndex == shard) {
                    found = &ref;
                    break;
                }
            }
            if (found == nullptr) {
                if (auto orphaned = rebuildOrphan(stripe, shard, shards[shard]); !orphaned) {
                    return std::unexpected(orphaned.error());
                }
                continue;
            }
            if (auto staged = journalWrite(found->payload.offset, shards[shard]); !staged) {
                return std::unexpected(staged.error());
            }
            touchedRecords_.insert(found->recordOffset);
            ++report_.repairedRecords;
        }
        if (auto fixed = fixTouchedRecords(); !fixed) {
            return std::unexpected(fixed.error());
        }
        report_.repaired = true;
        return {};
    }

    Result<bool> scatterShard(std::uint64_t shardOffset, std::span<const std::byte> shard) {
        std::uint64_t position = 0;
        bool mapped = false;
        auto shardEnd = checkedAdd(shardOffset, static_cast<std::uint64_t>(shard.size()));
        if (!shardEnd) {
            return fail(ErrorKind::LimitExceeded, "parity shard range overflows");
        }
        for (std::size_t index = 0; index < segments_.size(); ++index) {
            const auto& segment = segments_[index];
            auto segmentEnd = checkedAdd(position, segment.length);
            if (!segmentEnd) {
                return fail(ErrorKind::LimitExceeded, "parity stream range overflows");
            }
            std::uint64_t low = std::max(shardOffset, position);
            std::uint64_t high = std::min(*shardEnd, *segmentEnd);
            if (high > low) {
                auto rangeStart = checkedAdd(segment.fileOffset, low - position);
                if (!rangeStart) {
                    return fail(ErrorKind::LimitExceeded, "parity stream range overflows");
                }
                if (auto staged = journalWrite(
                        *rangeStart,
                        shard.subspan(
                            static_cast<std::size_t>(low - shardOffset),
                            static_cast<std::size_t>(high - low)
                        )
                    );
                    !staged) {
                    return std::unexpected(staged.error());
                }
                touchedRecords_.insert(segment.recordOffset);
                touchedSegments_.insert(index);
                report_.repairedBytes += high - low;
                mapped = true;
            }
            position = *segmentEnd;
        }
        if (*shardEnd > streamLength_) {
            mapped = true;
        }
        return mapped;
    }

    Result<void> rebuildOrphan(
        std::uint64_t stripe,
        std::uint32_t shardIndex,
        std::span<const std::byte> shard
    ) {
        if (!commitTrusted_) {
            return {};
        }
        const auto& descriptor = footer_.parity;
        std::uint32_t total = descriptor.dataShards + descriptor.parityShards;
        std::uint64_t wantLength =
            recordFramingSize + parityHeaderLength(total) + descriptor.shardBytes;
        std::uint64_t slot = 0;
        bool found = false;
        for (std::uint64_t candidate : orphans_) {
            const ScannedRecord* record = nullptr;
            for (const auto& scanned : scan_.records) {
                if (scanned.offset == candidate && scanned.type == RecordType::Parity) {
                    record = &scanned;
                    break;
                }
            }
            if (record != nullptr && record->length == wantLength) {
                slot = candidate;
                found = true;
                break;
            }
        }
        if (!found) {
            return {};
        }
        ParityHeader header;
        header.groupId = descriptor.groupId;
        header.generation = footer_.generation;
        header.stripeIndex = stripe;
        header.shardIndex = shardIndex;
        header.dataShards = descriptor.dataShards;
        header.parityShards = descriptor.parityShards;
        header.shardBytes = descriptor.shardBytes;
        header.stripeCount = descriptor.stripeCount;
        header.streamLength = streamLength_;
        header.crc.assign(total, 0);
        if (auto tabled = fillTable(header); !tabled) {
            return std::unexpected(tabled.error());
        }
        std::vector<std::byte> payload;
        if (!encodeParityRecord(header, shard, payload)) {
            return {};
        }
        if (auto staged = journalWrite(slot + recordPrefixSize, payload); !staged) {
            return std::unexpected(staged.error());
        }
        touchedRecords_.insert(slot);
        orphans_.erase(slot);
        ++report_.repairedRecords;
        return {};
    }

    Result<bool> fillTable(ParityHeader& header) {
        std::uint32_t total = header.dataShards + header.parityShards;
        std::uint64_t stripeStart = header.stripeIndex * stripeBytes_;
        for (std::uint32_t shard = 0; shard < total; ++shard) {
            std::vector<std::byte> bytes(header.shardBytes);
            if (shard < header.dataShards) {
                std::uint64_t streamOffset =
                    stripeStart + static_cast<std::uint64_t>(shard) * header.shardBytes;
                auto shardRead = readStripeShard(streamOffset, bytes);
                if (!shardRead) {
                    return std::unexpected(shardRead.error());
                }
                if (!*shardRead) {
                    return false;
                }
            } else {
                bool found = false;
                for (const auto& ref : parityRefs_) {
                    if (ref.header.stripeIndex == header.stripeIndex &&
                        ref.header.shardIndex == shard) {
                        auto refRead = readThrough(ref.payload.offset, bytes);
                        if (!refRead) {
                            return std::unexpected(refRead.error());
                        }
                        if (!*refRead) {
                            return false;
                        }
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return false;
                }
            }
            header.crc[shard] = Crc32c::of(bytes);
        }
        return true;
    }

    Result<void> fixTouchedRecords() {
        std::vector<std::byte> bytes;
        for (std::uint64_t recordOffset : touchedRecords_) {
            std::uint64_t recordLength = 0;
            for (const auto& segment : segments_) {
                if (segment.recordOffset == recordOffset) {
                    recordLength = segment.recordLength;
                    break;
                }
            }
            if (recordLength == 0) {
                for (const auto& ref : parityRefs_) {
                    if (ref.recordOffset == recordOffset) {
                        recordLength = ref.recordLength;
                        break;
                    }
                }
            }
            if (recordLength == 0) {
                for (const auto& scanned : scan_.records) {
                    if (scanned.offset == recordOffset) {
                        recordLength = scanned.length;
                        break;
                    }
                }
            }
            if (recordLength == 0) {
                continue;
            }
            bytes.resize(static_cast<std::size_t>(recordLength));
            auto recordRead = readThrough(recordOffset, bytes);
            if (!recordRead) {
                return std::unexpected(recordRead.error());
            }
            if (!*recordRead) {
                return fail(ErrorKind::Integrity, "touched record unreadable for reseal");
            }
            std::uint64_t payloadLength = recordLength - recordFramingSize;
            std::span<const std::byte> payload =
                std::span(bytes).subspan(recordPrefixSize, static_cast<std::size_t>(payloadLength));
            std::array<std::byte, recordTrailerSize> trailer{};
            storeLe(trailer.data(), Crc32c::of(payload));
            std::ranges::copy(recordEndMarker, trailer.begin() + 4);
            if (auto staged =
                    journalWrite(recordOffset + recordPrefixSize + payloadLength, trailer);
                !staged) {
                return std::unexpected(staged.error());
            }
            if (auto prefixFixed = fixPrefixCrc(recordOffset, recordLength, bytes); !prefixFixed) {
                return std::unexpected(prefixFixed.error());
            }
        }
        touchedRecords_.clear();
        return {};
    }

    Result<void> fixPrefixCrc(
        std::uint64_t recordOffset,
        std::uint64_t recordLength,
        std::span<const std::byte> record
    ) {
        if (record.size() < recordPrefixSize) {
            return {};
        }
        if (!std::ranges::equal(record.first(recordMagic.size()), recordMagic)) {
            return {};
        }
        auto type = loadLe<std::uint16_t>(record.data() + 4);
        if (type != static_cast<std::uint16_t>(RecordType::Data) &&
            type != static_cast<std::uint16_t>(RecordType::Manifest) &&
            type != static_cast<std::uint16_t>(RecordType::Index) &&
            type != static_cast<std::uint16_t>(RecordType::Commit) &&
            type != static_cast<std::uint16_t>(RecordType::Parity)) {
            return {};
        }
        if (loadLe<std::uint64_t>(record.data() + 8) != recordLength - recordFramingSize) {
            return {};
        }
        std::array<std::byte, recordPrefixSize> zeroed{};
        std::ranges::copy(record.first<recordPrefixSize>(), zeroed.begin());
        std::fill_n(zeroed.begin() + 36, 4, std::byte{0});
        std::uint32_t correct = Crc32c::of(zeroed);
        if (loadLe<std::uint32_t>(record.data() + 36) != correct) {
            std::array<std::byte, 4> encoded{};
            storeLe(encoded.data(), correct);
            if (auto staged = journalWrite(recordOffset + 36, encoded); !staged) {
                return std::unexpected(staged.error());
            }
        }
        return {};
    }

    Result<void> validateCompletedPayloads(
        std::uint64_t stripeEnd,
        ChunkDecoder& decoder,
        std::vector<std::byte>& recordBuffer
    ) {
        for (std::size_t index = 0; index < segments_.size(); ++index) {
            if (validated_.contains(index)) {
                continue;
            }
            std::uint64_t start = 0;
            for (std::size_t before = 0; before < index; ++before) {
                start += segments_[before].length;
            }
            std::uint64_t end = start + segments_[index].length;
            if (end > stripeEnd || !touchedSegments_.contains(index)) {
                continue;
            }
            if (auto checked = validateSegmentPayload(segments_[index], decoder, recordBuffer);
                !checked) {
                return std::unexpected(checked.error());
            }
            validated_.insert(index);
        }
        return {};
    }

    Result<void> validateSegmentPayload(
        const Segment& segment,
        ChunkDecoder& decoder,
        std::vector<std::byte>& recordBuffer
    ) {
        if (segment.recordLength < recordFramingSize ||
            segment.recordLength - recordFramingSize > repairMetaCap) {
            return fail(ErrorKind::LimitExceeded, "owning record exceeds the repair budget");
        }
        recordBuffer.resize(static_cast<std::size_t>(segment.recordLength));
        auto recordRead = readThrough(segment.recordOffset, recordBuffer);
        if (!recordRead) {
            return std::unexpected(recordRead.error());
        }
        if (!*recordRead) {
            return fail(ErrorKind::Integrity, "owning record unreadable for validation");
        }
        std::uint64_t payloadLength = segment.recordLength - recordFramingSize;
        std::span<const std::byte> payload =
            std::span(recordBuffer)
                .subspan(recordPrefixSize, static_cast<std::size_t>(payloadLength));
        std::uint64_t payloadOffset = segment.recordOffset + recordPrefixSize;
        switch (segment.kind) {
        case RecordType::Data:
            return verifyDataPayload(payload, payloadOffset, segment.codec, decoder);
        case RecordType::Index:
            return verifyOpaquePayload(payload, payloadOffset, HashDomain::Index, index_);
        case RecordType::Manifest:
            return verifyOpaquePayload(payload, payloadOffset, HashDomain::Manifest, manifestSpan_);
        case RecordType::Commit:
            return verifyCommitPayload(payload, payloadOffset);
        case RecordType::Extension:
            return verifyKeyslotPayload(payload, payloadOffset);
        case RecordType::Parity:
            return fail(ErrorKind::Malformed, "stripe data mapped to a parity record");
        }
        return fail(ErrorKind::Malformed, "stripe data has an unknown owner");
    }

    Result<void> verifyDataPayload(
        std::span<const std::byte> payload,
        std::uint64_t payloadOffset,
        CodecId codec,
        ChunkDecoder& decoder
    ) {
        if (!encrypted_) {
            auto data = decodeDataPayload(payload, payloadOffset);
            if (!data) {
                return std::unexpected(data.error());
            }
            if (data->key.length > maxChunkSize) {
                return fail(ErrorKind::LimitExceeded, "chunk exceeds the supported size");
            }
            std::vector<std::byte> decoded(static_cast<std::size_t>(data->key.length));
            if (codec == CodecId::Raw) {
                if (data->encoded.size() != data->key.length) {
                    return fail(ErrorKind::Integrity, "raw chunk length mismatch");
                }
                std::ranges::copy(data->encoded, decoded.begin());
            } else {
                if (auto out = decoder.decode(codec, data->encoded, decoded); !out) {
                    return std::unexpected(out.error());
                }
            }
            bool matches = chunkKeyOf(decoded).digest == data->key.digest;
            wipeBuffer(decoded);
            if (!matches) {
                return fail(ErrorKind::Integrity, "repaired chunk fails its content hash");
            }
            return {};
        }
        auto extent = decodeEncryptedExtent(payload, payloadOffset);
        if (!extent) {
            return std::unexpected(extent.error());
        }
        if (keys_ == nullptr) {
            return fail(ErrorKind::PasswordRequired, "encrypted repair needs keys");
        }
        if (extent->plain.length > maxChunkSize) {
            return fail(ErrorKind::LimitExceeded, "chunk exceeds the supported size");
        }
        if (payload.size() < encryptedDataHeaderSize) {
            return fail(ErrorKind::Integrity, "encrypted record too short");
        }
        std::uint64_t recordEpoch = loadLe<std::uint64_t>(payload.data() + 32);
        if (commitTrusted_ && recordEpoch != commit_.epoch) {
            return fail(ErrorKind::Integrity, "repaired record epoch disagrees with the commit");
        }
        for (const auto& [epoch, key] : keys_->byEpoch) {
            std::span<const std::byte, 16> id(keys_->archiveId.data(), 16);
            auto aad = dataAad(id, extent->object, codec, epoch);
            std::span<const std::byte> nonce = payload.subspan(40, crypto::nonceSize);
            std::span<const std::byte> boxed = payload.subspan(encryptedDataHeaderSize);
            auto opened = crypto::open(key.bytes(), nonce, boxed, aad);
            if (!opened) {
                if (opened.error().kind != ErrorKind::Integrity) {
                    return std::unexpected(opened.error());
                }
                continue;
            }
            std::vector<std::byte> decoded(static_cast<std::size_t>(extent->plain.length));
            Result<void> decodedOk;
            if (codec == CodecId::Raw) {
                if (opened->size() != decoded.size()) {
                    decodedOk = fail(ErrorKind::Integrity, "raw chunk length mismatch");
                } else {
                    std::ranges::copy(*opened, decoded.begin());
                    decodedOk = {};
                }
            } else {
                decodedOk = decoder.decode(codec, *opened, decoded);
            }
            wipeBuffer(*opened);
            if (!decodedOk) {
                if (decodedOk.error().kind == ErrorKind::Integrity) {
                    wipeBuffer(decoded);
                    continue;
                }
                wipeBuffer(decoded);
                return std::unexpected(decodedOk.error());
            }
            bool matches = chunkKeyOf(decoded).digest == extent->plain.digest;
            wipeBuffer(decoded);
            if (!matches) {
                return fail(ErrorKind::Integrity, "repaired chunk fails its content hash");
            }
            return {};
        }
        return fail(ErrorKind::Integrity, "no key authenticates the repaired record");
    }

    Result<void> verifyOpaquePayload(
        std::span<const std::byte> payload,
        std::uint64_t payloadOffset,
        HashDomain domain,
        const std::optional<MetaSpan>& trusted
    ) {
        std::span<const std::byte> plain = payload;
        std::vector<std::byte> opened;
        if (encrypted_) {
            if (keys_ == nullptr) {
                return fail(ErrorKind::PasswordRequired, "encrypted repair needs keys");
            }
            bool decrypted = false;
            for (const auto& [epoch, key] : keys_->byEpoch) {
                if (commitTrusted_ && epoch != commit_.epoch) {
                    continue;
                }
                if (payload.size() < crypto::nonceSize + crypto::tagSize) {
                    return fail(ErrorKind::Integrity, "encrypted metadata too short");
                }
                std::span<const std::byte, 16> id(keys_->archiveId.data(), 16);
                std::vector<std::byte> aad =
                    domain == HashDomain::Index ? indexAad(id, epoch) : manifestAad(id, epoch);
                auto attempt = crypto::open(
                    key.bytes(),
                    payload.first(crypto::nonceSize),
                    payload.subspan(crypto::nonceSize),
                    aad
                );
                if (!attempt) {
                    if (attempt.error().kind != ErrorKind::Integrity) {
                        return std::unexpected(attempt.error());
                    }
                    continue;
                }
                opened.assign(attempt->begin(), attempt->end());
                wipeBuffer(*attempt);
                decrypted = true;
                break;
            }
            if (!decrypted) {
                return fail(ErrorKind::Integrity, "no key authenticates the repaired metadata");
            }
            plain = opened;
        }
        Result<void> parsed;
        if (domain == HashDomain::Index) {
            std::vector<IndexEntry> entries;
            parsed = decodeIndex(
                plain,
                payloadOffset,
                std::numeric_limits<std::uint32_t>::max(),
                entries
            );
        } else {
            Manifest manifest;
            parsed = decodeManifest(plain, payloadOffset, limits_, manifest);
        }
        wipeBuffer(opened);
        if (!parsed) {
            return fail(ErrorKind::Integrity, "repaired metadata does not parse");
        }
        if (trusted && Blake3::of(domain, payload) != trusted->digest) {
            return fail(ErrorKind::Integrity, "repaired metadata fails its commit digest");
        }
        return {};
    }

    Result<void>
    verifyCommitPayload(std::span<const std::byte> payload, std::uint64_t payloadOffset) {
        if (!encrypted_) {
            auto commit = decodeCommit(payload, payloadOffset);
            if (!commit || commit->generation != footer_.generation) {
                return fail(ErrorKind::Integrity, "repaired commit does not parse");
            }
            if (Blake3::of(HashDomain::Commit, payload) != footer_.commitDigest) {
                return fail(ErrorKind::Integrity, "repaired commit fails its digest");
            }
            return {};
        }
        if (keys_ == nullptr) {
            return fail(ErrorKind::PasswordRequired, "encrypted repair needs keys");
        }
        for (const auto& [epoch, key] : keys_->byEpoch) {
            if (payload.size() < crypto::nonceSize + crypto::tagSize) {
                return fail(ErrorKind::Integrity, "encrypted commit too short");
            }
            std::span<const std::byte, 16> id(keys_->archiveId.data(), 16);
            auto aad = commitAad(id, epoch);
            auto opened = crypto::open(
                key.bytes(),
                payload.first(crypto::nonceSize),
                payload.subspan(crypto::nonceSize),
                aad
            );
            if (!opened) {
                if (opened.error().kind != ErrorKind::Integrity) {
                    return std::unexpected(opened.error());
                }
                continue;
            }
            auto commit = decodeCommit(*opened, payloadOffset);
            bool usable =
                commit && commit->generation == footer_.generation && commit->epoch == epoch;
            wipeBuffer(*opened);
            if (!usable) {
                continue;
            }
            if (Blake3::of(HashDomain::Commit, payload) != footer_.commitDigest) {
                return fail(ErrorKind::Integrity, "repaired commit fails its digest");
            }
            return {};
        }
        return fail(ErrorKind::Integrity, "no key authenticates the repaired commit");
    }

    Result<void>
    verifyKeyslotPayload(std::span<const std::byte> payload, std::uint64_t payloadOffset) {
        if (!decodeKeyslot(payload, payloadOffset)) {
            return fail(ErrorKind::Integrity, "repaired keyslot does not parse");
        }
        return {};
    }

    Result<void> adoptRecoveredCommit() {
        if (!commitSpan_) {
            return fail(ErrorKind::Integrity, "commit span missing for recovery");
        }
        Extent commitPayload = commitSpan_->payload;
        std::uint64_t commitOffset = commitSpan_->recordOffset;
        std::uint64_t commitLength = commitSpan_->recordLength;
        std::vector<std::byte> bytes(static_cast<std::size_t>(commitLength));
        auto commitRead = readThrough(commitOffset, bytes);
        if (!commitRead) {
            return std::unexpected(commitRead.error());
        }
        if (!*commitRead) {
            return fail(ErrorKind::Integrity, "recovered commit record still damaged");
        }
        RecordLimits commitLimits{
            .maxPayloadLength = encrypted_ ? maxEncryptedPayloadBytes : 4096,
            .maxDecodedLength = encrypted_ ? maxEncryptedPayloadBytes : 4096,
        };
        auto record = decodeRecord(bytes, commitLimits, commitOffset);
        if (!record) {
            return fail(ErrorKind::Integrity, "recovered commit record still damaged");
        }
        std::span<const std::byte> payload = std::span(bytes).subspan(
            recordPrefixSize,
            static_cast<std::size_t>(commitPayload.length)
        );
        if (!encrypted_) {
            auto commit = decodeCommit(payload, commitPayload.offset);
            if (!commit || commit->generation != footer_.generation) {
                return fail(ErrorKind::Integrity, "recovered commit does not parse");
            }
            return adoptOverlay(*commit);
        }
        if (keys_ == nullptr) {
            return fail(ErrorKind::PasswordRequired, "encrypted repair needs keys");
        }
        for (const auto& [epoch, key] : keys_->byEpoch) {
            std::span<const std::byte, 16> id(keys_->archiveId.data(), 16);
            auto aad = commitAad(id, epoch);
            auto opened = crypto::open(
                key.bytes(),
                payload.first(crypto::nonceSize),
                payload.subspan(crypto::nonceSize),
                aad
            );
            if (!opened) {
                if (opened.error().kind != ErrorKind::Integrity) {
                    return std::unexpected(opened.error());
                }
                continue;
            }
            auto commit = decodeCommit(*opened, commitPayload.offset);
            bool usable =
                commit && commit->generation == footer_.generation && commit->epoch == epoch;
            wipeBuffer(*opened);
            if (!usable) {
                continue;
            }
            return adoptOverlay(*commit);
        }
        return fail(ErrorKind::Integrity, "no key authenticates the recovered commit");
    }

    File& file_;
    const Limits& limits_;
    const RepairKeys* keys_;
    bool encrypted_;
    Footer footer_;
    std::uint64_t footerOffset_;
    std::uint64_t genStart_ = superblockSize;
    GenerationRepair report_;
    GenerationScan scan_;
    std::vector<DataSpan> data_;
    std::optional<MetaSpan> index_;
    std::optional<MetaSpan> manifestSpan_;
    std::optional<MetaSpan> commitSpan_;
    std::vector<Extent> keyslots_;
    std::vector<ParityRef> parityRefs_;
    std::set<std::uint64_t> orphans_;
    std::vector<Segment> segments_;
    std::uint64_t streamLength_ = 0;
    std::uint64_t stripeBytes_ = 0;
    std::uint64_t mappedPrefix_ = 0;
    bool commitTrusted_ = false;
    bool stopped_ = false;
    Commit commit_;
    std::vector<IndexEntry> indexEntries_;
    Manifest manifest_;
    std::vector<std::byte> indexBytes_;
    std::vector<std::byte> manifestBytes_;
    std::set<std::uint64_t> touchedRecords_;
    std::set<std::size_t> validated_;
    std::set<std::size_t> touchedSegments_;
    std::optional<std::uint64_t> cachedSize_;
    std::vector<JournalOp> journal_;
    std::uint64_t journalBytes_ = 0;
};

}

Result<RepairOutcome> repairParityGenerations(
    File& file,
    std::uint64_t fileSize,
    const Superblock& superblock,
    const Limits& limits,
    const RepairKeys* keys
) {
    RepairOutcome outcome;
    if ((superblock.requiredFeatures & parityRequiredFeature) == 0) {
        return outcome;
    }
    auto footers = collectFooters(file, fileSize);
    if (!footers) {
        return std::unexpected(footers.error());
    }
    for (auto iterator = footers->rbegin(); iterator != footers->rend(); ++iterator) {
        const auto& [footer, footerOffset] = *iterator;
        if (!footer.parity.present) {
            continue;
        }
        GenerationRepairer repairer(file, superblock, limits, keys, footer, footerOffset);
        auto report = repairer.run();
        if (!report) {
            return std::unexpected(report.error());
        }
        outcome.changed = outcome.changed || report->repaired;
        outcome.generations.push_back(*report);
    }
    return outcome;
}

}
