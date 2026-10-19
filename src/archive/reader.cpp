#include "archive/reader.hpp"

#include "archive/encrypted.hpp"
#include "base/checked.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>

namespace bale::archive {

namespace {

constexpr std::uint64_t maxDataPayload = 1 + maxDataDescriptorSize + maxChunkSize;
constexpr std::uint64_t maxCommitPayload = 4096;

bool spansOverlap(std::uint64_t offset, std::uint64_t length, const RecordReference& record) {
    return offset < record.offset + record.length && record.offset < offset + length;
}

}

Result<Reader> Reader::open(File file, const ReaderOptions& options) {
    auto size = file.size();
    if (!size) {
        return std::unexpected(size.error());
    }
    if (*size < superblockSize) {
        return fail(ErrorKind::Truncated, "file too small for a superblock", *size);
    }

    Reader reader(std::move(file), options, *size);
    std::array<std::byte, superblockSize> block{};
    auto read = reader.file_.readExactAt(0, block);
    if (!read) {
        return std::unexpected(read.error());
    }

    auto superblock = decodeSuperblock(block);
    if (!superblock) {
        return std::unexpected(superblock.error());
    }
    reader.superblock_ = *superblock;
    if ((reader.superblock_.requiredFeatures & encryptedRequiredFeature) != 0) {
        return fail(ErrorKind::PasswordRequired, "archive is encrypted");
    }

    auto found = reader.findCommit();
    if (!found) {
        return std::unexpected(found.error());
    }
    return reader;
}

Result<Record> Reader::readRecord(
    std::uint64_t offset,
    std::uint64_t length,
    RecordType type,
    std::uint64_t maxPayload,
    std::vector<std::byte>& buffer
) {
    if (offset < superblockSize || !fitsWithin(offset, length, fileSize_)) {
        return fail(ErrorKind::Malformed, "record reference outside the file", offset);
    }
    if (length < recordFramingSize) {
        return fail(ErrorKind::Malformed, "record reference shorter than framing", offset);
    }
    if (length - recordFramingSize > maxPayload) {
        return fail(ErrorKind::LimitExceeded, "record payload exceeds limit", offset);
    }

    buffer.resize(static_cast<std::size_t>(length));
    auto read = file_.readExactAt(offset, buffer);
    if (!read) {
        return std::unexpected(read.error());
    }

    RecordLimits limits{
        .maxPayloadLength = maxPayload,
        .maxDecodedLength = maxPayload,
    };
    auto record = decodeRecord(buffer, limits, offset);
    if (!record) {
        return std::unexpected(record.error());
    }
    if (record->size != length) {
        return fail(ErrorKind::Malformed, "record length differs from its reference", offset);
    }
    if (record->header.type != type) {
        return fail(ErrorKind::Malformed, "record has an unexpected type", offset);
    }
    return *record;
}

Result<void> Reader::loadMetadata() {
    const RecordReference& manifest = commit_.manifest;
    const RecordReference& index = commit_.index;
    for (const RecordReference* record : {&manifest, &index}) {
        if (record->offset < superblockSize ||
            !fitsWithin(record->offset, record->length, footer_.commitOffset)) {
            return fail(ErrorKind::Malformed, "metadata record outside the committed region");
        }
    }
    if (spansOverlap(manifest.offset, manifest.length, index)) {
        return fail(ErrorKind::Malformed, "manifest and index records overlap");
    }

    auto manifestRecord = readRecord(
        manifest.offset,
        manifest.length,
        RecordType::Manifest,
        options_.maxMetadataBytes,
        manifestBytes_
    );
    if (!manifestRecord) {
        return std::unexpected(manifestRecord.error());
    }
    if (manifestRecord->header.codec != CodecId::Raw) {
        return fail(ErrorKind::Unsupported, "compressed manifest records are not supported");
    }
    if (Blake3::of(HashDomain::Manifest, manifestRecord->payload) != manifest.digest) {
        return fail(ErrorKind::Integrity, "manifest digest mismatch", manifest.offset);
    }

    auto indexRecord = readRecord(
        index.offset,
        index.length,
        RecordType::Index,
        options_.maxMetadataBytes,
        indexBytes_
    );
    if (!indexRecord) {
        return std::unexpected(indexRecord.error());
    }
    if (indexRecord->header.codec != CodecId::Raw) {
        return fail(ErrorKind::Unsupported, "compressed index records are not supported");
    }
    if (Blake3::of(HashDomain::Index, indexRecord->payload) != index.digest) {
        return fail(ErrorKind::Integrity, "index digest mismatch", index.offset);
    }

    auto decodedIndex = decodeIndex(
        indexRecord->payload,
        index.offset + recordPrefixSize,
        std::numeric_limits<std::uint32_t>::max(),
        index_
    );
    if (!decodedIndex) {
        return decodedIndex;
    }

    auto decodedManifest = decodeManifest(
        manifestRecord->payload,
        manifest.offset + recordPrefixSize,
        options_.limits,
        manifest_
    );
    if (!decodedManifest) {
        return decodedManifest;
    }

    for (const auto& key : manifest_.chunks) {
        if (findChunk(index_, key) == nullptr) {
            return fail(
                ErrorKind::Malformed,
                "manifest references a chunk missing from the index",
                manifest.offset
            );
        }
    }
    return {};
}

Result<void> Reader::checkLocations() {
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
        if (entry.recordOffset < previousEnd) {
            return fail(ErrorKind::Malformed, "indexed records overlap", entry.recordOffset);
        }
        if (!fitsWithin(entry.recordOffset, entry.recordLength, footer_.commitOffset) ||
            spansOverlap(entry.recordOffset, entry.recordLength, commit_.manifest) ||
            spansOverlap(entry.recordOffset, entry.recordLength, commit_.index)) {
            return fail(
                ErrorKind::Malformed,
                "indexed record overlaps metadata or the commit",
                entry.recordOffset
            );
        }
        previousEnd = entry.recordOffset + entry.recordLength;

        if (entry.codec != CodecId::Raw) {
            continue;
        }
        auto descriptor = encodeDataDescriptor(entry.key, descriptor_);
        if (!descriptor) {
            return descriptor;
        }
        if (entry.recordLength != recordFramingSize + descriptor_.size() + entry.key.length) {
            return fail(
                ErrorKind::Malformed,
                "indexed raw record length does not match its chunk",
                entry.recordOffset
            );
        }
    }
    return {};
}

Result<std::span<const std::byte>> Reader::loadChunk(const ChunkKey& key) {
    const IndexEntry* entry = findChunk(index_, key);
    if (entry == nullptr) {
        return fail(ErrorKind::Malformed, "chunk missing from the index");
    }

    auto record = readRecord(
        entry->recordOffset,
        entry->recordLength,
        RecordType::Data,
        maxDataPayload,
        buffer_
    );
    if (!record) {
        return std::unexpected(record.error());
    }
    if (record->header.codec != entry->codec) {
        return fail(
            ErrorKind::Malformed,
            "data record codec differs from the index",
            entry->recordOffset
        );
    }

    auto payloadOffset = entry->recordOffset + recordPrefixSize;
    auto data = decodeDataPayload(record->payload, payloadOffset);
    if (!data) {
        return std::unexpected(data.error());
    }
    if (data->key != key) {
        return fail(
            ErrorKind::Malformed,
            "data record holds a different chunk than indexed",
            payloadOffset
        );
    }
    if (record->header.decodedLength != data->descriptorSize + key.length) {
        return fail(
            ErrorKind::Malformed,
            "data record decoded length does not match its chunk",
            entry->recordOffset
        );
    }

    std::span<const std::byte> decoded;
    if (record->header.codec == CodecId::Raw) {
        if (data->encoded.size() != key.length) {
            return fail(
                ErrorKind::Malformed,
                "raw chunk length does not match its key",
                payloadOffset
            );
        }
        decoded = data->encoded;
    } else {
        if (key.length > maxChunkSize) {
            return fail(ErrorKind::LimitExceeded, "compressed chunk exceeds the supported size");
        }

        decodedBuffer_.resize(static_cast<std::size_t>(key.length));
        auto decodedChunk =
            chunkDecoder_.decode(record->header.codec, data->encoded, decodedBuffer_);
        if (!decodedChunk) {
            auto error = decodedChunk.error();
            std::uint64_t encodedOffset = payloadOffset + data->descriptorSize;
            error.offset =
                error.offset == Error::noOffset ? encodedOffset : encodedOffset + error.offset;
            return std::unexpected(error);
        }
        decoded = decodedBuffer_;
    }

    if (chunkKeyOf(decoded).digest != key.digest) {
        return fail(
            ErrorKind::Integrity,
            "chunk content does not match its BLAKE3 digest",
            payloadOffset + data->descriptorSize
        );
    }
    return decoded;
}

Result<VerifyReport> Reader::walkRecords() {
    VerifyReport report;
    std::uint64_t maxPayload = std::max(options_.maxMetadataBytes, maxDataPayload);
    if (encrypted_) {
        maxPayload += encryptedDataHeaderSize + crypto::tagSize + encryptedMetaNonceSize;
    }
    RecordLimits limits{
        .maxPayloadLength = maxPayload,
        .maxDecodedLength = maxPayload,
    };

    std::array<std::byte, recordPrefixSize> prefix{};
    std::uint64_t position = superblockSize;
    std::size_t nextIndexed = 0;
    std::size_t generation = 0;
    std::vector<std::byte> metadata;
    while (position < footerOffset_) {
        if (generation < generations_.size() && position == generations_[generation].footerOffset) {
            position += footerSize;
            ++generation;
            continue;
        }
        if (footerOffset_ - position < recordFramingSize) {
            return fail(ErrorKind::Malformed, "stray bytes before the footer", position);
        }
        auto read = file_.readExactAt(position, prefix);
        if (!read) {
            return std::unexpected(read.error());
        }

        auto header = decodeRecordPrefix(prefix, limits, position);
        if (!header) {
            return std::unexpected(header.error());
        }
        std::uint64_t size = header->payloadLength + recordFramingSize;
        if (!fitsWithin(position, size, footerOffset_)) {
            return fail(ErrorKind::Malformed, "record extends past the footer", position);
        }
        if (header->sequence != report.records) {
            return fail(ErrorKind::Malformed, "record sequence number out of order", position);
        }

        bool expected = true;
        bool isEncryptedRecord = (header->flags & encryptedRecordFlag) != 0;
        if (encrypted_) {
            if (!isEncryptedRecord) {
                return fail(
                    ErrorKind::Malformed,
                    "plain record inside an encrypted archive",
                    position
                );
            }
        } else if (isEncryptedRecord) {
            return fail(ErrorKind::Unsupported, "encrypted record in a plain archive", position);
        }
        switch (header->type) {
        case RecordType::Data:
            ++report.dataRecords;
            if (nextIndexed < byOffset_.size() &&
                index_[byOffset_[nextIndexed]].recordOffset == position) {
                const IndexEntry& entry = index_[byOffset_[nextIndexed]];
                expected = entry.recordLength == size && entry.codec == header->codec;
                ++nextIndexed;
            } else {
                ++report.unindexedDataRecords;
            }
            break;
        case RecordType::Manifest:
            expected = generation < generations_.size() &&
                position == generations_[generation].commit.manifest.offset &&
                size == generations_[generation].commit.manifest.length;
            if (expected) {
                auto record = readRecord(
                    position,
                    size,
                    RecordType::Manifest,
                    options_.maxMetadataBytes,
                    metadata
                );
                if (!record) {
                    return std::unexpected(record.error());
                }
                expected = Blake3::of(HashDomain::Manifest, record->payload) ==
                    generations_[generation].commit.manifest.digest;
            }
            break;
        case RecordType::Index:
            expected = generation < generations_.size() &&
                position == generations_[generation].commit.index.offset &&
                size == generations_[generation].commit.index.length;
            if (expected) {
                auto record = readRecord(
                    position,
                    size,
                    RecordType::Index,
                    options_.maxMetadataBytes,
                    metadata
                );
                if (!record) {
                    return std::unexpected(record.error());
                }
                expected = Blake3::of(HashDomain::Index, record->payload) ==
                    generations_[generation].commit.index.digest;
            }
            break;
        case RecordType::Commit:
            expected = generation < generations_.size() &&
                position == generations_[generation].footer.commitOffset &&
                size == generations_[generation].footer.commitLength;
            if (expected) {
                auto record =
                    readRecord(position, size, RecordType::Commit, maxCommitPayload, metadata);
                if (!record) {
                    return std::unexpected(record.error());
                }
                expected = Blake3::of(HashDomain::Commit, record->payload) ==
                    generations_[generation].digest;
            }
            break;
        case RecordType::Extension:
            break;
        }
        if (!expected) {
            return fail(
                ErrorKind::Malformed,
                "record does not match the committed metadata",
                position
            );
        }

        ++report.records;
        position += size;
    }

    if (nextIndexed != byOffset_.size()) {
        return fail(ErrorKind::Malformed, "index entry does not point at a record boundary");
    }
    if (generation + 1 != generations_.size()) {
        return fail(ErrorKind::Malformed, "generation footer is missing from the record stream");
    }
    return report;
}

Result<VerifyReport> Reader::verify(VerifyMode mode) {
    auto report = walkRecords();
    if (!report || mode == VerifyMode::Structure) {
        return report;
    }

    if (!encrypted_) {
        for (const auto& entry : index_) {
            auto chunk = loadChunk(entry.key);
            if (!chunk) {
                return std::unexpected(chunk.error());
            }
            ++report->chunksVerified;
            report->bytesVerified += chunk->size();
        }
        return report;
    }

    for (const auto& entry : manifest_.entries) {
        if (entry.kind != EntryKind::Regular) {
            continue;
        }
        auto objects = std::span(manifest_.objectIds).subspan(entry.firstChunk, entry.chunkCount);
        auto plains = manifest_.chunksOf(entry);
        for (std::size_t index = 0; index < plains.size(); ++index) {
            auto chunk = loadEncryptedExtent(objects[index], plains[index]);
            if (!chunk) {
                return std::unexpected(chunk.error());
            }
            ++report->chunksVerified;
            report->bytesVerified += chunk->size();
        }
    }
    return report;
}

}
