#include "archive/commit.hpp"

#include "format/tlv.hpp"

#include <algorithm>
#include <array>

namespace bale::archive {

namespace {

constexpr std::uint32_t versionField = 1;
constexpr std::uint32_t generationField = 2;
constexpr std::uint32_t previousField = 3;
constexpr std::uint32_t featuresField = 4;
constexpr std::uint32_t manifestOffsetField = 5;
constexpr std::uint32_t indexOffsetField = 8;
constexpr std::uint32_t manifestLengthField = manifestOffsetField + 1;
constexpr std::uint32_t manifestDigestField = manifestOffsetField + 2;
constexpr std::uint32_t indexLengthField = indexOffsetField + 1;
constexpr std::uint32_t indexDigestField = indexOffsetField + 2;
constexpr std::uint32_t previousFooterField = 12;

constexpr bool isDigestField(std::uint32_t number) {
    return number == previousField || number == manifestDigestField || number == indexDigestField;
}

Result<void> writeDigest(TlvWriter& writer, std::uint32_t number, const Blake3Digest& digest) {
    return writer.bytes(number, Criticality::Critical, digest);
}

Result<void>
writeRecord(TlvWriter& writer, std::uint32_t offsetField, const RecordReference& record) {
    auto offset = writer.unsignedValue(offsetField, Criticality::Critical, record.offset);
    if (!offset) {
        return offset;
    }
    auto length = writer.unsignedValue(offsetField + 1, Criticality::Critical, record.length);
    if (!length) {
        return length;
    }
    return writeDigest(writer, offsetField + 2, record.digest);
}

}

Result<void> encodeCommit(const Commit& commit, std::vector<std::byte>& out) {
    out.clear();
    TlvWriter writer(out);
    auto version = writer.unsignedValue(versionField, Criticality::Critical, commitSchemaVersion);
    if (!version) {
        return version;
    }
    auto generation =
        writer.unsignedValue(generationField, Criticality::Critical, commit.generation);
    if (!generation) {
        return generation;
    }
    auto previous = writeDigest(writer, previousField, commit.previous);
    if (!previous) {
        return previous;
    }
    auto features =
        writer.unsignedValue(featuresField, Criticality::Critical, commit.requiredFeatures);
    if (!features) {
        return features;
    }
    auto manifest = writeRecord(writer, manifestOffsetField, commit.manifest);
    if (!manifest) {
        return manifest;
    }
    auto index = writeRecord(writer, indexOffsetField, commit.index);
    if (!index) {
        return index;
    }
    if (commit.generation == 1) {
        return {};
    }
    return writer
        .unsignedValue(previousFooterField, Criticality::Noncritical, commit.previousFooterOffset);
}

Result<Commit> decodeCommit(std::span<const std::byte> payload, std::uint64_t offset) {
    Commit commit;
    std::array<std::uint64_t, indexDigestField + 1> values{};
    std::array<Blake3Digest*, indexDigestField + 1> digests{};
    digests[previousField] = &commit.previous;
    digests[manifestDigestField] = &commit.manifest.digest;
    digests[indexDigestField] = &commit.index.digest;

    TlvReader reader(payload, offset);
    TlvField field;
    std::uint32_t seen = 0;
    bool hasPreviousFooter = false;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return std::unexpected(more.error());
        }
        if (!*more) {
            break;
        }

        if (field.number == previousFooterField) {
            auto critical = requireCriticality(field, Criticality::Noncritical);
            if (!critical) {
                return std::unexpected(critical.error());
            }
            if (hasPreviousFooter) {
                return fail(ErrorKind::Malformed, "duplicate previous footer field", field.offset);
            }
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return std::unexpected(value.error());
            }
            commit.previousFooterOffset = *value;
            hasPreviousFooter = true;
            continue;
        }
        if (field.number > indexDigestField) {
            auto skipped = skipUnknownField(field);
            if (!skipped) {
                return std::unexpected(skipped.error());
            }
            continue;
        }

        auto critical = requireCriticality(field, Criticality::Critical);
        if (!critical) {
            return std::unexpected(critical.error());
        }
        seen |= std::uint32_t{1} << field.number;

        if (isDigestField(field.number)) {
            if (field.value.size() != blake3DigestSize) {
                return fail(ErrorKind::Malformed, "commit digest is not 32 bytes", field.offset);
            }
            std::ranges::copy(field.value, digests[field.number]->begin());
            continue;
        }

        auto value = decodeTlvUnsigned(field);
        if (!value) {
            return std::unexpected(value.error());
        }
        values[field.number] = *value;
    }

    constexpr std::uint32_t allFields = ((std::uint32_t{1} << (indexDigestField + 1)) - 1) & ~1U;
    if (seen != allFields) {
        return fail(ErrorKind::Malformed, "commit missing a required field", offset);
    }
    if (values[versionField] != commitSchemaVersion) {
        return fail(ErrorKind::Unsupported, "unsupported commit schema version", offset);
    }
    if ((values[featuresField] & ~knownCommitFeatures) != 0) {
        return fail(ErrorKind::Unsupported, "unknown required commit feature", offset);
    }
    if (values[generationField] == 0) {
        return fail(ErrorKind::Malformed, "commit generation zero", offset);
    }
    if (values[generationField] > 1 && !hasPreviousFooter) {
        return fail(ErrorKind::Malformed, "commit is missing its previous footer", offset);
    }
    if (values[generationField] == 1 && hasPreviousFooter) {
        return fail(ErrorKind::Malformed, "first generation has a previous footer", offset);
    }

    commit.generation = values[generationField];
    commit.requiredFeatures = values[featuresField];
    commit.manifest.offset = values[manifestOffsetField];
    commit.manifest.length = values[manifestLengthField];
    commit.index.offset = values[indexOffsetField];
    commit.index.length = values[indexLengthField];
    return commit;
}

}
