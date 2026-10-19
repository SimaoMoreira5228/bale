#include "archive/encrypted.hpp"
#include "archive/reader.hpp"
#include "base/checked.hpp"
#include "base/endian.hpp"

#include <sodium/utils.h>

#include <algorithm>
#include <map>

namespace bale::archive {

namespace {

constexpr std::uint64_t maxLocalDataPayload = 1 + maxDataDescriptorSize + maxChunkSize;

std::span<const std::byte, 16> idSpan(const std::array<std::byte, 16>& id) {
    return std::span<const std::byte, 16>(id.data(), 16);
}

void wipeBytes(std::vector<std::byte>& bytes) {
    if (!bytes.empty()) {
        sodium_memzero(bytes.data(), bytes.size());
    }
}

Result<std::map<std::uint64_t, crypto::SecretBytes>>
collectKeys(File& file, std::uint64_t fileSize, ReaderUnlock& unlock, const Limits& limits) {
    std::map<std::uint64_t, crypto::SecretBytes> keys;
    std::vector<std::byte> recordBuffer;
    std::uint64_t position = superblockSize;
    std::uint64_t slotsSeen = 0;
    RecordLimits recordLimits{
        .maxPayloadLength = maxEncryptedPayloadBytes,
        .maxDecodedLength = maxEncryptedPayloadBytes,
    };
    std::array<std::byte, recordPrefixSize> prefix{};
    std::array<std::byte, footerSize> footerBytes{};
    (void)limits;
    while (position < fileSize) {
        if (fileSize - position >= footerSize) {
            auto peek = file.readExactAt(position, std::span<std::byte>(footerBytes));
            if (!peek) {
                return std::unexpected(peek.error());
            }
            if (std::ranges::equal(std::span(footerBytes).first(footerMagic.size()), footerMagic)) {
                auto footer = decodeFooter(footerBytes, position);
                if (footer) {
                    position += footerSize;
                    continue;
                }
            }
        }
        if (fileSize - position < recordFramingSize) {
            break;
        }
        auto read = file.readExactAt(position, std::span<std::byte>(prefix));
        if (!read) {
            return std::unexpected(read.error());
        }
        auto header = decodeRecordPrefix(prefix, recordLimits, position);
        if (!header) {
            break;
        }
        auto size = recordSize(header->payloadLength);
        if (!size || !fitsWithin(position, *size, fileSize)) {
            break;
        }
        if (header->type != RecordType::Extension || (header->flags & encryptedRecordFlag) == 0) {
            position += *size;
            continue;
        }
        if (header->payloadLength > 4096) {
            return fail(ErrorKind::LimitExceeded, "keyslot payload too large", position);
        }
        recordBuffer.resize(static_cast<std::size_t>(*size));
        auto full = file.readExactAt(position, recordBuffer);
        if (!full) {
            return std::unexpected(full.error());
        }
        auto record = decodeRecord(recordBuffer, recordLimits, position);
        if (!record) {
            return std::unexpected(record.error());
        }
        auto slot = decodeKeyslot(record->payload, position + recordPrefixSize);
        if (!slot) {
            return std::unexpected(slot.error());
        }
        // NOTE: count every keyslot record so a hostile archive cannot force unbounded KDF
        // work; decodeKeyslot already rejected over-cap params, so reaching unwrap is bounded.
        ++slotsSeen;
        if (slotsSeen > maxKeyslotsPerArchive) {
            return fail(ErrorKind::LimitExceeded, "too many keyslots", position);
        }
        if (keys.contains(slot->epoch)) {
            position += *size;
            continue;
        }
        bool unlocked = false;
        crypto::SecretBytes key;
        if (slot->kind == SlotKind::Password && unlock.hasPassword) {
            crypto::PasswordSlot pw;
            pw.epoch = slot->epoch;
            pw.salt = slot->salt;
            pw.opslimit = slot->opslimit;
            pw.memlimitBytes = slot->memlimitBytes;
            pw.nonce = slot->nonce;
            pw.wrapped = slot->wrapped;
            auto back = crypto::unwrapPasswordKey(pw, unlock.password.bytes());
            if (back) {
                key = std::move(*back);
                unlocked = true;
            } else if (back.error().kind != ErrorKind::Integrity) {
                return std::unexpected(back.error());
            }
        } else if (slot->kind == SlotKind::Recipient) {
            for (const auto& recipient : unlock.recipients) {
                if (recipient.publicKey != slot->recipientPublic) {
                    continue;
                }
                crypto::RecipientSlot sealed;
                sealed.sealed = slot->sealed;
                auto back = crypto::unwrapRecipientKey(
                    sealed,
                    recipient.publicKey,
                    recipient.secretKey.bytes()
                );
                if (back) {
                    key = std::move(*back);
                    unlocked = true;
                    break;
                } else if (back.error().kind != ErrorKind::Integrity) {
                    return std::unexpected(back.error());
                }
            }
        }
        if (unlocked) {
            keys.emplace(slot->epoch, std::move(key));
        }
        position += *size;
    }
    return keys;
}

Result<std::pair<Footer, std::uint64_t>>
findLatestFooterOffset(File& file, std::uint64_t fileSize, const ReaderOptions& options) {
    std::uint64_t window = std::min(
        std::max<std::uint64_t>(options.footerScanBlockSize, footerSize),
        std::uint64_t{1} << 20
    );
    std::uint64_t end = fileSize;
    std::uint64_t previousStart = fileSize;
    std::vector<std::byte> block;
    constexpr std::size_t maxCandidates = 64;
    std::size_t attempts = 0;
    std::optional<Error> nearest;
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
                        auto decoded = decodeFooter(candidate, candidateOffset);
                        if (decoded) {
                            return std::pair<Footer, std::uint64_t>{*decoded, candidateOffset};
                        }
                        if (!nearest) {
                            nearest = decoded.error();
                        }
                        ++attempts;
                        if (attempts == maxCandidates) {
                            break;
                        }
                    }
                }
                if (at == 0 || attempts == maxCandidates) {
                    break;
                }
            }
        }
        if (start == superblockSize || attempts == maxCandidates) {
            break;
        }
        previousStart = start;
        end = start + footerSize - 1;
    }
    if (nearest) {
        return std::unexpected(*nearest);
    }
    return fail(ErrorKind::Truncated, "no footer found: the archive is incomplete or truncated");
}

}

Result<Reader>
Reader::openEncrypted(File file, const ReaderOptions& options, ReaderUnlock&& unlock) {
    auto size = file.size();
    if (!size) {
        return std::unexpected(size.error());
    }
    if (*size < superblockSize) {
        return fail(ErrorKind::Truncated, "file too small for a superblock", *size);
    }
    Reader reader(std::move(file), options, *size);
    std::array<std::byte, superblockSize> block{};
    if (auto read = reader.file_.readExactAt(0, block); !read) {
        return std::unexpected(read.error());
    }
    auto superblock = decodeSuperblock(block);
    if (!superblock) {
        return std::unexpected(superblock.error());
    }
    reader.superblock_ = *superblock;
    if ((reader.superblock_.requiredFeatures & encryptedRequiredFeature) == 0) {
        return fail(ErrorKind::Malformed, "archive is not encrypted");
    }

    auto keys = collectKeys(reader.file_, reader.fileSize_, unlock, options.limits);
    if (!keys) {
        return std::unexpected(keys.error());
    }
    if (keys->empty()) {
        return fail(ErrorKind::PasswordRequired, "no keyslot could be unlocked");
    }

    auto latest = findLatestFooterOffset(reader.file_, reader.fileSize_, options);
    if (!latest) {
        return std::unexpected(latest.error());
    }
    Footer footer = latest->first;
    std::uint64_t footerOffset = latest->second;

    std::vector<std::byte> commitBuffer(static_cast<std::size_t>(footer.commitLength));
    if (auto read = reader.file_.readExactAt(footer.commitOffset, commitBuffer); !read) {
        return std::unexpected(read.error());
    }
    RecordLimits commitLimits{
        .maxPayloadLength = maxEncryptedPayloadBytes,
        .maxDecodedLength = maxEncryptedPayloadBytes,
    };
    auto commitRecord = decodeRecord(commitBuffer, commitLimits, footer.commitOffset);
    if (!commitRecord) {
        return std::unexpected(commitRecord.error());
    }
    if (commitRecord->header.type != RecordType::Commit ||
        (commitRecord->header.flags & encryptedRecordFlag) == 0) {
        return fail(ErrorKind::Malformed, "commit is not marked encrypted", footer.commitOffset);
    }
    if (Blake3::of(HashDomain::Commit, commitRecord->payload) != footer.commitDigest) {
        return fail(ErrorKind::Integrity, "commit digest mismatch", footer.commitOffset);
    }
    if (commitRecord->payload.size() < crypto::nonceSize + crypto::tagSize) {
        return fail(ErrorKind::Truncated, "encrypted commit too short", footer.commitOffset);
    }

    bool decrypted = false;
    Commit commit;
    crypto::SecretBytes dataKey;
    std::uint64_t epoch = 0;
    for (auto& [candidateEpoch, candidateKey] : *keys) {
        std::span<const std::byte> nonce =
            std::span(commitRecord->payload).first(crypto::nonceSize);
        std::span<const std::byte> boxed =
            std::span(commitRecord->payload).subspan(crypto::nonceSize);
        auto aad = commitAad(idSpan(reader.superblock_.archiveId), candidateEpoch);
        auto opened = crypto::open(candidateKey.bytes(), nonce, boxed, aad);
        if (!opened) {
            if (opened.error().kind == ErrorKind::Integrity) {
                continue;
            }
            return std::unexpected(opened.error());
        }
        auto decoded = decodeCommit(*opened, footer.commitOffset + recordPrefixSize);
        if (!decoded) {
            wipeBytes(*opened);
            continue;
        }
        if (decoded->generation != footer.generation ||
            (decoded->requiredFeatures & encryptedCommitFeature) == 0 ||
            decoded->epoch != candidateEpoch) {
            wipeBytes(*opened);
            continue;
        }
        commit = *decoded;
        dataKey = std::move(candidateKey);
        epoch = candidateEpoch;
        wipeBytes(*opened);
        decrypted = true;
        break;
    }
    if (!decrypted) {
        return fail(ErrorKind::Integrity, "commit authentication failed", footer.commitOffset);
    }

    reader.encrypted_ = true;
    reader.epoch_ = epoch;
    reader.dataKey_ = std::move(dataKey);
    reader.footer_ = footer;
    reader.footerOffset_ = footerOffset;
    reader.commit_ = commit;
    reader.commitDigest_ = footer.commitDigest;
    reader.generations_.clear();
    reader.generations_.push_back(
        Generation{
            .footer = footer,
            .commit = commit,
            .digest = footer.commitDigest,
            .footerOffset = footerOffset
        }
    );

    // NOTE: walk the parent chain decrypting each parent commit to build the full
    // NOTE: generation list for structural validation. Old epochs stay readable with the same
    // NOTE: password because each generation has its own slots.
    {
        Commit current = commit;
        std::uint64_t currentFooterOffset = footerOffset;
        while (current.generation > 1) {
            if (reader.generations_.size() >= options.maxGenerations) {
                return fail(ErrorKind::LimitExceeded, "archive generation limit exceeded");
            }
            if (current.previous == Blake3Digest{} ||
                current.previousFooterOffset >= currentFooterOffset) {
                return fail(ErrorKind::Malformed, "invalid previous commit footer");
            }
            std::array<std::byte, footerSize> parentBytes{};
            if (auto read = reader.file_.readExactAt(current.previousFooterOffset, parentBytes);
                !read) {
                return std::unexpected(read.error());
            }
            auto parentFooter = decodeFooter(parentBytes, current.previousFooterOffset);
            if (!parentFooter) {
                return std::unexpected(parentFooter.error());
            }
            if (parentFooter->generation + 1 != current.generation ||
                parentFooter->commitDigest != current.previous) {
                return fail(
                    ErrorKind::Integrity,
                    "previous footer does not match commit chain",
                    current.previousFooterOffset
                );
            }
            std::vector<std::byte> parentBuffer(
                static_cast<std::size_t>(parentFooter->commitLength)
            );
            if (auto read = reader.file_.readExactAt(parentFooter->commitOffset, parentBuffer);
                !read) {
                return std::unexpected(read.error());
            }
            auto parentRecord =
                decodeRecord(parentBuffer, commitLimits, parentFooter->commitOffset);
            if (!parentRecord) {
                return std::unexpected(parentRecord.error());
            }
            if (Blake3::of(HashDomain::Commit, parentRecord->payload) !=
                parentFooter->commitDigest) {
                return fail(
                    ErrorKind::Integrity,
                    "parent commit digest mismatch",
                    parentFooter->commitOffset
                );
            }
            bool found = false;
            Commit parentCommit;
            for (auto& [candidateEpoch, candidateKey] : *keys) {
                std::span<const std::byte> nonce =
                    std::span(parentRecord->payload).first(crypto::nonceSize);
                std::span<const std::byte> boxed =
                    std::span(parentRecord->payload).subspan(crypto::nonceSize);
                auto aad = commitAad(idSpan(reader.superblock_.archiveId), candidateEpoch);
                auto opened = crypto::open(candidateKey.bytes(), nonce, boxed, aad);
                if (!opened) {
                    if (opened.error().kind == ErrorKind::Integrity) {
                        continue;
                    }
                    return std::unexpected(opened.error());
                }
                auto decoded = decodeCommit(*opened, parentFooter->commitOffset + recordPrefixSize);
                wipeBytes(*opened);
                if (!decoded) {
                    continue;
                }
                if (decoded->generation != parentFooter->generation ||
                    (decoded->requiredFeatures & encryptedCommitFeature) == 0 ||
                    decoded->epoch != candidateEpoch) {
                    continue;
                }
                parentCommit = *decoded;
                found = true;
                break;
            }
            if (!found) {
                return fail(
                    ErrorKind::Integrity,
                    "parent commit authentication failed",
                    parentFooter->commitOffset
                );
            }
            reader.generations_.push_back(
                Generation{
                    .footer = *parentFooter,
                    .commit = parentCommit,
                    .digest = parentFooter->commitDigest,
                    .footerOffset = current.previousFooterOffset,
                }
            );
            current = parentCommit;
            // NOTE: track the footer we just validated; the next iteration uses its offset.
            currentFooterOffset = reader.generations_.back().footerOffset;
        }
        std::ranges::reverse(reader.generations_);
    }

    if (auto metadata = reader.loadMetadataEncrypted(); !metadata) {
        return std::unexpected(metadata.error());
    }
    if (auto locations = reader.checkLocationsEncrypted(); !locations) {
        return std::unexpected(locations.error());
    }
    if (auto report = reader.walkRecords(); !report) {
        return std::unexpected(report.error());
    } else {
        reader.sequenceCount_ = report->records;
    }
    return reader;
}

Result<void> Reader::loadMetadataEncrypted() {
    const RecordReference& manifest = commit_.manifest;
    const RecordReference& index = commit_.index;
    for (const RecordReference* record : {&manifest, &index}) {
        if (record->offset < superblockSize ||
            !fitsWithin(record->offset, record->length, footer_.commitOffset)) {
            return fail(ErrorKind::Malformed, "metadata record outside the committed region");
        }
    }

    auto manifestRecord = readRecord(
        manifest.offset,
        manifest.length,
        RecordType::Manifest,
        options_.maxMetadataBytes + encryptedMetaNonceSize + crypto::tagSize,
        manifestBytes_
    );
    if (!manifestRecord) {
        return std::unexpected(manifestRecord.error());
    }
    if ((manifestRecord->header.flags & encryptedRecordFlag) == 0) {
        return fail(ErrorKind::Malformed, "manifest is not marked encrypted", manifest.offset);
    }
    if (Blake3::of(HashDomain::Manifest, manifestRecord->payload) != manifest.digest) {
        return fail(ErrorKind::Integrity, "manifest digest mismatch", manifest.offset);
    }
    if (manifestRecord->payload.size() < crypto::nonceSize + crypto::tagSize) {
        return fail(ErrorKind::Truncated, "encrypted manifest too short", manifest.offset);
    }
    std::span<const std::byte> manifestNonce =
        std::span(manifestRecord->payload).first(crypto::nonceSize);
    std::span<const std::byte> manifestBoxed =
        std::span(manifestRecord->payload).subspan(crypto::nonceSize);
    auto manifestAadBytes = manifestAad(idSpan(superblock_.archiveId), epoch_);
    auto manifestPlain =
        crypto::open(dataKey_.bytes(), manifestNonce, manifestBoxed, manifestAadBytes);
    if (!manifestPlain) {
        return std::unexpected(manifestPlain.error());
    }
    plainBuffer_.assign(manifestPlain->begin(), manifestPlain->end());
    wipeBytes(*manifestPlain);
    auto decodedManifest = decodeManifest(
        plainBuffer_,
        manifest.offset + recordPrefixSize,
        options_.limits,
        manifest_
    );
    if (!decodedManifest) {
        return std::unexpected(decodedManifest.error());
    }
    if (manifest_.objectIds.size() != manifest_.chunks.size()) {
        return fail(
            ErrorKind::Malformed,
            "manifest object count differs from chunks",
            manifest.offset
        );
    }

    auto indexRecord = readRecord(
        index.offset,
        index.length,
        RecordType::Index,
        options_.maxMetadataBytes + encryptedMetaNonceSize + crypto::tagSize,
        indexBytes_
    );
    if (!indexRecord) {
        return std::unexpected(indexRecord.error());
    }
    if ((indexRecord->header.flags & encryptedRecordFlag) == 0) {
        return fail(ErrorKind::Malformed, "index is not marked encrypted", index.offset);
    }
    if (Blake3::of(HashDomain::Index, indexRecord->payload) != index.digest) {
        return fail(ErrorKind::Integrity, "index digest mismatch", index.offset);
    }
    if (indexRecord->payload.size() < crypto::nonceSize + crypto::tagSize) {
        return fail(ErrorKind::Truncated, "encrypted index too short", index.offset);
    }
    std::span<const std::byte> indexNonce =
        std::span(indexRecord->payload).first(crypto::nonceSize);
    std::span<const std::byte> indexBoxed =
        std::span(indexRecord->payload).subspan(crypto::nonceSize);
    auto indexAadBytes = indexAad(idSpan(superblock_.archiveId), epoch_);
    auto indexPlain = crypto::open(dataKey_.bytes(), indexNonce, indexBoxed, indexAadBytes);
    if (!indexPlain) {
        return std::unexpected(indexPlain.error());
    }
    std::vector<std::byte> indexPlainBuffer(indexPlain->begin(), indexPlain->end());
    wipeBytes(*indexPlain);
    auto decodedIndex = decodeIndex(
        indexPlainBuffer,
        index.offset + recordPrefixSize,
        std::numeric_limits<std::uint32_t>::max(),
        index_
    );
    if (!decodedIndex) {
        return decodedIndex;
    }
    for (const auto& object : manifest_.objectIds) {
        bool found = false;
        for (const auto& entry : index_) {
            if (entry.key.algorithm == HashAlgorithm::EncryptedObject &&
                entry.key.digest == object) {
                found = true;
                break;
            }
        }
        if (!found) {
            return fail(
                ErrorKind::Malformed,
                "manifest references a chunk missing from the index",
                index.offset
            );
        }
    }
    return {};
}

Result<void> Reader::checkLocationsEncrypted() {
    byOffset_.resize(index_.size());
    for (std::size_t position = 0; position < index_.size(); ++position) {
        byOffset_[position] = static_cast<std::uint32_t>(position);
    }
    std::ranges::sort(byOffset_, {}, [this](std::uint32_t position) {
        return index_[position].recordOffset;
    });

    std::uint64_t previousEnd = superblockSize;
    for (std::uint32_t position : byOffset_) {
        const IndexEntry& entry = index_[position];
        if (entry.key.algorithm != HashAlgorithm::EncryptedObject) {
            return fail(
                ErrorKind::Malformed,
                "encrypted index has a plain chunk id",
                entry.recordOffset
            );
        }
        if (entry.recordOffset < previousEnd) {
            return fail(ErrorKind::Malformed, "indexed records overlap", entry.recordOffset);
        }
        if (!fitsWithin(entry.recordOffset, entry.recordLength, footer_.commitOffset)) {
            return fail(
                ErrorKind::Malformed,
                "indexed record overlaps metadata or the commit",
                entry.recordOffset
            );
        }
        previousEnd = entry.recordOffset + entry.recordLength;
    }
    return {};
}

Result<std::span<const std::byte>>
Reader::loadEncryptedExtent(const std::array<std::byte, 32>& object, const ChunkKey& plain) {
    const IndexEntry* found = nullptr;
    for (const auto& entry : index_) {
        if (entry.key.algorithm == HashAlgorithm::EncryptedObject && entry.key.digest == object) {
            found = &entry;
            break;
        }
    }
    if (found == nullptr) {
        return fail(ErrorKind::Malformed, "chunk missing from the index");
    }
    auto record = readRecord(
        found->recordOffset,
        found->recordLength,
        RecordType::Data,
        maxLocalDataPayload + encryptedDataHeaderSize + crypto::tagSize,
        buffer_
    );
    if (!record) {
        return std::unexpected(record.error());
    }
    if ((record->header.flags & encryptedRecordFlag) == 0) {
        return fail(
            ErrorKind::Malformed,
            "data record is not marked encrypted",
            found->recordOffset
        );
    }
    if (record->header.codec != found->codec) {
        return fail(
            ErrorKind::Malformed,
            "data record codec differs from the index",
            found->recordOffset
        );
    }
    if (record->payload.size() < encryptedDataHeaderSize + crypto::tagSize) {
        return fail(ErrorKind::Truncated, "encrypted data record too short", found->recordOffset);
    }
    ObjectId recordObject{};
    std::ranges::copy(record->payload.first(32), recordObject.begin());
    if (recordObject != object) {
        return fail(
            ErrorKind::Malformed,
            "data record holds a different object",
            found->recordOffset
        );
    }
    std::uint64_t recordEpoch = loadLe<std::uint64_t>(record->payload.data() + 32);
    if (recordEpoch != epoch_) {
        return fail(
            ErrorKind::Malformed,
            "data record epoch differs from the commit",
            found->recordOffset
        );
    }
    std::array<std::byte, 24> nonce{};
    std::ranges::copy(record->payload.subspan(40, 24), nonce.begin());
    std::span<const std::byte> boxed = record->payload.subspan(encryptedDataHeaderSize);
    ObjectId aadObject = object;
    auto aad = dataAad(idSpan(superblock_.archiveId), aadObject, record->header.codec, epoch_);
    auto sealed = crypto::open(dataKey_.bytes(), nonce, boxed, aad);
    if (!sealed) {
        return std::unexpected(sealed.error());
    }
    std::span<const std::byte> compressed(*sealed);
    std::span<const std::byte> decoded;
    if (record->header.codec == CodecId::Raw) {
        if (compressed.size() != plain.length) {
            wipeBytes(*sealed);
            return fail(
                ErrorKind::Malformed,
                "raw chunk length does not match its key",
                found->recordOffset
            );
        }
        decodedBuffer_.assign(compressed.begin(), compressed.end());
        wipeBytes(*sealed);
        decoded = decodedBuffer_;
    } else {
        if (plain.length > maxChunkSize) {
            wipeBytes(*sealed);
            return fail(ErrorKind::LimitExceeded, "compressed chunk exceeds the supported size");
        }
        decodedBuffer_.resize(static_cast<std::size_t>(plain.length));
        auto out = chunkDecoder_.decode(record->header.codec, compressed, decodedBuffer_);
        wipeBytes(*sealed);
        if (!out) {
            return std::unexpected(out.error());
        }
        decoded = decodedBuffer_;
    }
    // NOTE: content-hash failure is distinct from tag failure: tag failures surface as
    // NOTE: Integrity from crypto::open above, while a digest mismatch here is Malformed.
    if (decoded.size() != plain.length || chunkKeyOf(decoded).digest != plain.digest) {
        return fail(
            ErrorKind::Malformed,
            "chunk content does not match its BLAKE3 digest",
            found->recordOffset + encryptedDataHeaderSize
        );
    }
    return decoded;
}

}
