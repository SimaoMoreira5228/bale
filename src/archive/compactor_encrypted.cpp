#include "archive/encrypted.hpp"
#include "archive/reader.hpp"
#include "archive/signatures.hpp"
#include "archive/writer.hpp"

#include <algorithm>

namespace bale::archive {

Result<WriteSummary> Writer::compactEncrypted(File file, Reader& source, bool durable) {
    return compactEncrypted(std::move(file), source, durable, {});
}

Result<WriteSummary> Writer::compactEncrypted(
    File file,
    Reader& source,
    bool durable,
    std::vector<crypto::SecretBytes> signSeeds
) {
    if (!source.encrypted_) {
        return fail(ErrorKind::Malformed, "source is not encrypted");
    }
    auto verified = source.verify(VerifyMode::Structure);
    if (!verified) {
        return std::unexpected(verified.error());
    }
    // NOTE: same refuse-or-carry rule as the plain compactor: signatures bind the old commit
    // NOTE: digest, so a signed source needs explicit re-signing keys.
    if (source.hasSignatures() && signSeeds.empty()) {
        return fail(
            ErrorKind::Malformed,
            "source is signed; pass signing keys to re-sign the compacted archive"
        );
    }

    std::vector<bool> reachable(source.index_.size(), false);
    for (const auto& object : source.manifest_.objectIds) {
        const IndexEntry* found = nullptr;
        for (const auto& entry : source.index_) {
            if (entry.key.algorithm == HashAlgorithm::EncryptedObject &&
                entry.key.digest == object) {
                found = &entry;
                break;
            }
        }
        if (found == nullptr) {
            return fail(ErrorKind::Malformed, "manifest references a missing chunk");
        }
        std::size_t position = static_cast<std::size_t>(found - source.index_.data());
        reachable[position] = true;
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
    options.workers = 1;
    options.experimentalEncryption = true;
    if (source.footer_.parity.present) {
        options.parity.enabled = true;
        options.parity.dataShards = source.footer_.parity.dataShards;
        options.parity.parityShards = source.footer_.parity.parityShards;
        options.parity.shardBytes = source.footer_.parity.shardBytes;
    }

    auto madeKey = crypto::SecretBytes::make(source.dataKey_.size());
    if (!madeKey) {
        return std::unexpected(madeKey.error());
    }
    crypto::SecretBytes cloned(std::move(*madeKey));
    std::ranges::copy(source.dataKey_.bytes(), cloned.mut().begin());

    Writer writer(std::move(file), options);
    writer.encrypted_ = true;
    writer.epoch_ = source.epoch_;
    writer.dataKey_ = std::move(cloned);
    writer.archiveId_ = source.superblock_.archiveId;
    for (auto& seed : signSeeds) {
        if (auto added = writer.addSignSeed(std::move(seed)); !added) {
            return std::unexpected(added.error());
        }
    }
    if (auto started = writer.startPipeline(); !started) {
        return std::unexpected(started.error());
    }
    Superblock superblock;
    superblock.archiveId = writer.archiveId_;
    superblock.creationTimeNs = source.superblock_.creationTimeNs;
    superblock.requiredFeatures = encryptedRequiredFeature;
    if (options.parity.enabled) {
        superblock.requiredFeatures |= parityRequiredFeature;
    }
    if (auto written = writer.appendRaw(encodeSuperblock(superblock)); !written) {
        return std::unexpected(written.error());
    }

    // NOTE: copy KEYSLOT Extension records verbatim (new sequence, same payload and flags).
    {
        RecordLimits keyLimits{
            .maxPayloadLength = maxEncryptedPayloadBytes,
            .maxDecodedLength = maxEncryptedPayloadBytes,
        };
        std::vector<std::byte> recordBytes;
        std::uint64_t position = superblockSize;
        std::array<std::byte, footerSize> footerPeek{};
        while (position < source.footerOffset_) {
            bool isFooter = false;
            if (source.footerOffset_ - position >= footerSize) {
                if (auto peek =
                        source.file_.readExactAt(position, std::span<std::byte>(footerPeek));
                    peek) {
                    if (std::ranges::equal(
                            std::span(footerPeek).first(footerMagic.size()),
                            footerMagic
                        )) {
                        position += footerSize;
                        isFooter = true;
                    }
                }
            }
            if (isFooter) {
                continue;
            }
            std::array<std::byte, recordPrefixSize> prefix{};
            if (auto read = source.file_.readExactAt(position, prefix); !read) {
                return std::unexpected(read.error());
            }
            auto header = decodeRecordPrefix(prefix, keyLimits, position);
            if (!header) {
                return std::unexpected(header.error());
            }
            auto size = recordSize(header->payloadLength);
            if (!size) {
                return std::unexpected(size.error());
            }
            recordBytes.resize(static_cast<std::size_t>(*size));
            if (auto read = source.file_.readExactAt(position, recordBytes); !read) {
                return std::unexpected(read.error());
            }
            auto record = decodeRecord(recordBytes, keyLimits, position);
            if (!record) {
                return std::unexpected(record.error());
            }
            if (record->header.type == RecordType::Extension &&
                (record->header.flags & encryptedRecordFlag) != 0) {
                // NOTE: SIGNATURE records bind the old commit digest, so they are never carried;
                // NOTE: only KEYSLOT records survive compaction. The refuse-or-carry check above
                // NOTE: guarantees a signed source is re-signed instead of silently dropped.
                auto kind = peekExtensionKind(record->payload, position + recordPrefixSize);
                if (!kind) {
                    return std::unexpected(kind.error());
                }
                if (*kind != keyslotExtensionKind) {
                    position += *size;
                    continue;
                }
                auto copied = writer.writeRecord(
                    RecordType::Extension,
                    record->payload,
                    {},
                    CodecId::Raw,
                    0,
                    encryptedRecordFlag
                );
                if (!copied) {
                    return std::unexpected(copied.error());
                }
            }
            position += *size;
            if (position >= source.footer_.commitOffset &&
                position < source.footerOffset_ + footerSize) {
                // NOTE: footer handling above skips footers; continue scanning.
            }
        }
    }

    writer.inheritedWriter_ = source.manifest_.writer;
    writer.names_.reserve(nameBytes);
    writer.entries_.reserve(source.manifest_.entries.size());
    writer.chunks_.assign(source.manifest_.chunks.begin(), source.manifest_.chunks.end());
    writer.objectIds_.assign(source.manifest_.objectIds.begin(), source.manifest_.objectIds.end());
    writer.index_.reserve(source.index_.size());
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

    RecordLimits dataLimits{
        .maxPayloadLength = maxChunkSize + encryptedDataHeaderSize + crypto::tagSize + 1024,
        .maxDecodedLength = maxChunkSize + encryptedDataHeaderSize + crypto::tagSize + 1024,
    };
    for (std::uint32_t position : source.byOffset_) {
        if (!reachable[position]) {
            continue;
        }
        const IndexEntry& entry = source.index_[position];
        auto record = source.readRecord(
            entry.recordOffset,
            entry.recordLength,
            RecordType::Data,
            maxChunkSize + encryptedDataHeaderSize + crypto::tagSize + 1024,
            source.buffer_
        );
        if (!record) {
            return std::unexpected(record.error());
        }
        if ((record->header.flags & encryptedRecordFlag) == 0) {
            return fail(
                ErrorKind::Malformed,
                "plain record inside encrypted archive",
                entry.recordOffset
            );
        }
        auto copied = writer.writeRecord(
            RecordType::Data,
            record->payload,
            {},
            record->header.codec,
            record->header.decodedLength,
            encryptedRecordFlag
        );
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
        (void)dataLimits;
    }

    return writer.finish();
}

}
