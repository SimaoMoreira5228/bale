#include "archive/reader.hpp"

#include "archive/signatures.hpp"

#include <array>

namespace bale::archive {

Result<void> Reader::loadSignatures() {
    signatures_.clear();
    return checkTrailerRecords(footer_.commitOffset + footer_.commitLength, footerOffset_, true);
}

Result<void>
Reader::checkTrailerRecords(std::uint64_t commitEnd, std::uint64_t footerOffset, bool store) {
    if (commitEnd > footerOffset) {
        return fail(ErrorKind::Malformed, "commit record does not precede footer", commitEnd);
    }

    RecordLimits limits{
        .maxPayloadLength = maxSignaturePayloadBytes,
        .maxDecodedLength = maxSignaturePayloadBytes,
    };
    std::uint16_t wantFlags = encrypted_ ? encryptedRecordFlag : 0;
    std::vector<std::byte> recordBytes;
    std::uint64_t position = commitEnd;
    std::uint64_t trailerSignatures = 0;
    while (position < footerOffset) {
        if (footerOffset - position < recordFramingSize) {
            return fail(ErrorKind::Malformed, "stray bytes after the commit record", position);
        }
        std::array<std::byte, recordPrefixSize> prefix{};
        if (auto read = file_.readExactAt(position, prefix); !read) {
            return std::unexpected(read.error());
        }
        auto header = decodeRecordPrefix(prefix, limits, position);
        if (!header) {
            return std::unexpected(header.error());
        }
        auto size = recordSize(header->payloadLength);
        if (!size) {
            return std::unexpected(size.error());
        }
        if (!fitsWithin(position, *size, footerOffset)) {
            return fail(ErrorKind::Malformed, "record extends past the footer", position);
        }
        if (header->type != RecordType::Extension) {
            return fail(ErrorKind::Malformed, "unexpected record after the commit", position);
        }
        if (header->flags != wantFlags) {
            return fail(ErrorKind::Malformed, "trailer record has unexpected flags", position);
        }
        recordBytes.resize(static_cast<std::size_t>(*size));
        if (auto read = file_.readExactAt(position, recordBytes); !read) {
            return std::unexpected(read.error());
        }
        auto record = decodeRecord(recordBytes, limits, position);
        if (!record) {
            return std::unexpected(record.error());
        }
        auto kind = peekExtensionKind(record->payload, position + recordPrefixSize);
        if (!kind) {
            return std::unexpected(kind.error());
        }
        // NOTE: the commit trailer carries signatures and nothing else; an unknown
        // NOTE: Extension here is rejected so stray bytes cannot hide behind the new gap.
        if (*kind != signatureExtensionKind) {
            return fail(
                ErrorKind::Unsupported,
                "unknown extension in the commit trailer",
                position
            );
        }
        if (trailerSignatures >= maxSignaturesPerCommit) {
            return fail(ErrorKind::LimitExceeded, "too many signatures", position);
        }
        ++trailerSignatures;
        auto signature = decodeSignature(record->payload, position + recordPrefixSize);
        if (!signature) {
            return std::unexpected(signature.error());
        }
        if (store) {
            signatures_.push_back(*signature);
        }
        position += *size;
    }
    return {};
}

Result<void>
Reader::verifySignatures(std::span<const std::array<std::byte, signerIdSize>> keys) const {
    if (keys.empty()) {
        return fail(ErrorKind::Malformed, "no verification key was given");
    }
    if (signatures_.empty()) {
        return fail(ErrorKind::Integrity, "archive has no signatures", footerOffset_);
    }
    std::span<const std::byte, 16> id(superblock_.archiveId.data(), 16);
    std::span<const std::byte, 32> digest(commitDigest_.data(), 32);
    for (const auto& key : keys) {
        std::span<const std::byte> keySpan(key.data(), key.size());
        for (const auto& signature : signatures_) {
            auto checked =
                checkSignature(signature, keySpan, id, commit_.generation, commit_.epoch, digest);
            if (checked) {
                return {};
            }
            if (checked.error().kind != ErrorKind::Integrity) {
                return std::unexpected(checked.error());
            }
        }
    }
    return fail(ErrorKind::Integrity, "no signature from the verification key verifies");
}

}
