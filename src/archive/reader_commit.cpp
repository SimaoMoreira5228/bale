#include "archive/reader.hpp"

#include "base/checked.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <utility>

namespace bale::archive {

namespace {

constexpr std::size_t maxFooterCandidates = 64;
constexpr std::uint64_t maxCommitPayload = 4096;
constexpr std::uint64_t maxFooterScanBlock = std::uint64_t{1} << 20;

bool spansOverlap(std::uint64_t offset, std::uint64_t length, const RecordReference& record) {
    return offset < record.offset + record.length && record.offset < offset + length;
}

}

Result<void> Reader::findCommit() {
    if (fileSize_ - superblockSize < footerSize) {
        return fail(
            ErrorKind::Truncated,
            "no footer found: the archive is incomplete or truncated"
        );
    }

    std::uint64_t window = std::min(
        std::max<std::uint64_t>(options_.footerScanBlockSize, footerSize),
        maxFooterScanBlock
    );
    std::uint64_t end = fileSize_;
    std::optional<Error> nearest;
    std::size_t attempts = 0;
    std::uint64_t previousStart = fileSize_;
    std::vector<std::byte> block;
    while (end > superblockSize) {
        std::uint64_t start = superblockSize;
        if (end - superblockSize > window) {
            start = end - window;
        }

        block.resize(static_cast<std::size_t>(end - start));
        auto read = file_.readExactAt(start, block);
        if (!read) {
            return read;
        }

        if (block.size() >= footerSize) {
            for (std::size_t at = block.size() - footerSize;; --at) {
                std::uint64_t candidateOffset = start + at;
                if (candidateOffset < previousStart) {
                    auto candidate = std::span(block).subspan(at, footerSize);
                    if (std::ranges::equal(candidate.first(footerMagic.size()), footerMagic)) {
                        auto decoded = decodeFooter(candidate, candidateOffset);
                        if (!decoded) {
                            if (!nearest) {
                                nearest = decoded.error();
                            }
                        } else {
                            auto accepted = tryFooter(candidate, candidateOffset);
                            if (accepted) {
                                return {};
                            }
                            if (!nearest) {
                                nearest = accepted.error();
                            }
                            ++attempts;
                            if (attempts == maxFooterCandidates) {
                                break;
                            }
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

    if (nearest) {
        return tl::unexpected<Error>(*nearest);
    }
    return fail(ErrorKind::Truncated, "no footer found: the archive is incomplete or truncated");
}

Result<void> Reader::tryFooter(std::span<const std::byte> bytes, std::uint64_t offset) {
    auto footer = decodeFooter(bytes, offset);
    if (!footer) {
        return tl::unexpected<Error>(footer.error());
    }
    if (footer->commitOffset + footer->commitLength > offset) {
        return fail(ErrorKind::Malformed, "footer does not directly follow its commit", offset);
    }

    auto record = readRecord(
        footer->commitOffset,
        footer->commitLength,
        RecordType::Commit,
        maxCommitPayload,
        buffer_
    );
    if (!record) {
        return tl::unexpected<Error>(record.error());
    }
    if (record->header.codec != CodecId::Raw) {
        return fail(ErrorKind::Malformed, "commit record is not stored raw", footer->commitOffset);
    }

    auto digest = Blake3::of(HashDomain::Commit, record->payload);
    if (digest != footer->commitDigest) {
        return fail(ErrorKind::Integrity, "commit digest mismatch", footer->commitOffset);
    }

    auto commit = decodeCommit(record->payload, footer->commitOffset + recordPrefixSize);
    if (!commit) {
        return tl::unexpected<Error>(commit.error());
    }
    if (commit->generation != footer->generation) {
        return fail(ErrorKind::Malformed, "footer and commit disagree on generation", offset);
    }
    std::vector<Generation> generations;
    generations.push_back(
        Generation{
            .footer = *footer,
            .commit = *commit,
            .digest = digest,
            .footerOffset = offset,
        }
    );

    Commit parentCommit = *commit;
    while (parentCommit.generation > 1) {
        if (generations.size() >= options_.maxGenerations) {
            return fail(ErrorKind::LimitExceeded, "archive generation limit exceeded", offset);
        }
        if (parentCommit.previous == Blake3Digest{} ||
            parentCommit.previousFooterOffset >= generations.back().footerOffset ||
            !fitsWithin(
                parentCommit.previousFooterOffset,
                footerSize,
                generations.back().footerOffset
            )) {
            return fail(ErrorKind::Malformed, "invalid previous commit footer", offset);
        }

        std::array<std::byte, footerSize> parentBytes{};
        auto parentRead = file_.readExactAt(parentCommit.previousFooterOffset, parentBytes);
        if (!parentRead) {
            return tl::unexpected<Error>(parentRead.error());
        }
        auto decodedFooter = decodeFooter(parentBytes, parentCommit.previousFooterOffset);
        if (!decodedFooter) {
            return tl::unexpected<Error>(decodedFooter.error());
        }
        if (decodedFooter->generation + 1 != parentCommit.generation ||
            decodedFooter->commitDigest != parentCommit.previous) {
            return fail(
                ErrorKind::Integrity,
                "previous footer does not match commit chain",
                offset
            );
        }
        std::uint64_t parentCommitEnd = decodedFooter->commitOffset + decodedFooter->commitLength;
        if (parentCommitEnd > parentCommit.previousFooterOffset) {
            return fail(
                ErrorKind::Malformed,
                "parent commit record does not precede its footer",
                offset
            );
        }
        // NOTE: a signed parent leaves SIGNATURE records between its commit and its
        // NOTE: footer; the gap must validate as a trailer exactly like the latest one.
        if (auto trailer = checkTrailerRecords(
                parentCommitEnd,
                parentCommit.previousFooterOffset,
                false,
                decodedFooter->parity,
                decodedFooter->generation
            );
            !trailer) {
            return tl::unexpected<Error>(trailer.error());
        }

        auto parentRecord = readRecord(
            decodedFooter->commitOffset,
            decodedFooter->commitLength,
            RecordType::Commit,
            maxCommitPayload,
            buffer_
        );
        if (!parentRecord) {
            return tl::unexpected<Error>(parentRecord.error());
        }
        if (parentRecord->header.codec != CodecId::Raw) {
            return fail(
                ErrorKind::Malformed,
                "commit record is not stored raw",
                decodedFooter->commitOffset
            );
        }

        auto decodedCommit =
            decodeCommit(parentRecord->payload, decodedFooter->commitOffset + recordPrefixSize);
        if (!decodedCommit) {
            return tl::unexpected<Error>(decodedCommit.error());
        }
        Blake3Digest parentDigest = Blake3::of(HashDomain::Commit, parentRecord->payload);
        if (parentDigest != decodedFooter->commitDigest ||
            decodedCommit->generation != decodedFooter->generation ||
            decodedCommit->generation + 1 != parentCommit.generation) {
            return fail(
                ErrorKind::Integrity,
                "parent commit does not match footer",
                decodedFooter->commitOffset
            );
        }

        for (const RecordReference* reference : {&decodedCommit->manifest, &decodedCommit->index}) {
            if (reference->offset < superblockSize ||
                !fitsWithin(reference->offset, reference->length, decodedFooter->commitOffset)) {
                return fail(
                    ErrorKind::Malformed,
                    "parent metadata reference outside its generation"
                );
            }
        }
        if (spansOverlap(
                decodedCommit->manifest.offset,
                decodedCommit->manifest.length,
                decodedCommit->index
            )) {
            return fail(ErrorKind::Malformed, "parent metadata records overlap");
        }
        auto validateParentMetadata = [&](const RecordReference& reference,
                                          RecordType type,
                                          HashDomain domain) -> Result<void> {
            auto metadataRecord = readRecord(
                reference.offset,
                reference.length,
                type,
                options_.maxMetadataBytes,
                buffer_
            );
            if (!metadataRecord) {
                return tl::unexpected<Error>(metadataRecord.error());
            }
            if (metadataRecord->header.codec != CodecId::Raw ||
                Blake3::of(domain, metadataRecord->payload) != reference.digest) {
                return fail(
                    ErrorKind::Integrity,
                    "parent metadata record failed validation",
                    reference.offset
                );
            }
            return {};
        };
        auto manifestChecked = validateParentMetadata(
            decodedCommit->manifest,
            RecordType::Manifest,
            HashDomain::Manifest
        );
        if (!manifestChecked) {
            return manifestChecked;
        }
        auto indexChecked =
            validateParentMetadata(decodedCommit->index, RecordType::Index, HashDomain::Index);
        if (!indexChecked) {
            return indexChecked;
        }

        generations.push_back(
            Generation{
                .footer = *decodedFooter,
                .commit = *decodedCommit,
                .digest = parentDigest,
                .footerOffset = parentCommit.previousFooterOffset,
            }
        );
        parentCommit = *decodedCommit;
    }
    if (parentCommit.previous != Blake3Digest{} || parentCommit.generation != 1) {
        return fail(ErrorKind::Malformed, "first generation has a parent commit", offset);
    }
    std::ranges::reverse(generations);

    footer_ = *footer;
    footerOffset_ = offset;
    commit_ = *commit;
    commitDigest_ = digest;
    generations_ = std::move(generations);

    auto metadata = loadMetadata();
    if (!metadata) {
        return metadata;
    }
    if (auto signatures = loadSignatures(); !signatures) {
        return signatures;
    }
    return checkLocations();
}

}
