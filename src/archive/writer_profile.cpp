#include "archive/writer_profile.hpp"

#include <span>

namespace bale::archive {

namespace {

constexpr std::uint32_t nameField = 1;
constexpr std::uint32_t presetField = 2;
constexpr std::uint32_t codecField = 3;
constexpr std::uint32_t levelField = 4;
constexpr std::uint32_t chunkPolicyField = 5;
constexpr std::uint32_t chunkSizeField = 6;
constexpr std::uint32_t reservedDictionaryField = 7;
constexpr std::uint32_t workersField = 8;
constexpr std::uint32_t chunkMinField = 9;
constexpr std::uint32_t chunkTargetField = 10;
constexpr std::uint32_t chunkMaxField = 11;
constexpr std::uint32_t chunkAlgorithmField = 12;

struct PresetPolicy {
    Preset preset;
    std::string_view name;
    CodecId codec;
    std::int32_t level;
};

// NOTE: levels chosen from bench/results/2026-10-18-*; read those summaries before changing one.
// NOTE: lzma2 was measured against zstd:19 in bench/results/2026-10-19-xeon-e5-2690v3-lzma2 and
// rejected for `small`: at most 1.8% smaller archives on mixed data, worse on code and small
// files, for 2-3x slower end-to-end runs, ~9x slower single-file extraction and higher create
// RSS. lzma2 stays an explicit --codec, not a preset.
// NOTE: brotli was measured the same way in bench/results/2026-10-19-xeon-e5-2690v3-brotli and
// rejected too, despite a real size win (quality 11: 9% smaller on source, 7% on structured,
// tie on prose; quality 6: 6% smaller on small files and faster to create than zstd:19).
// Quality 11 saves the same 0.2 of 14.5 MiB on mixed data for 8-9x slower create and
// 2.2-2.4x slower single-file extraction, and quality 6 loses prose by 15%, so `small`
// stays zstd:19 and brotli stays an explicit --codec, not a preset.
constexpr std::array presetPolicies{
    PresetPolicy{
        .preset = Preset::Fast,
        .name = "fast",
        .codec = CodecId::Lz4,
        .level = 0,
    },
    PresetPolicy{
        .preset = Preset::Balanced,
        .name = "balanced",
        .codec = CodecId::Zstd,
        .level = 3,
    },
    PresetPolicy{
        .preset = Preset::Small,
        .name = "small",
        .codec = CodecId::Zstd,
        .level = 19,
    },
    PresetPolicy{
        .preset = Preset::RestoreFast,
        .name = "restore-fast",
        .codec = CodecId::Lz4,
        .level = 0,
    },
    PresetPolicy{
        .preset = Preset::Portable,
        .name = "portable",
        .codec = CodecId::Zstd,
        .level = 3,
    },
};

const PresetPolicy& policyOf(Preset preset) {
    for (const PresetPolicy& policy : presetPolicies) {
        if (policy.preset == preset) {
            return policy;
        }
    }
    return presetPolicies[1];
}

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text));
}

Result<void>
putUnsigned(TlvWriter& writer, std::uint32_t number, std::optional<std::uint64_t> value) {
    if (!value) {
        return {};
    }
    return writer.unsignedValue(number, Criticality::Noncritical, *value);
}

}

CompressionProfile profileFor(Preset preset) {
    const PresetPolicy& policy = policyOf(preset);
    return CompressionProfile{
        .preset = preset,
        .codec = policy.codec,
        .level = policy.level,
    };
}

std::string_view presetName(Preset preset) {
    return policyOf(preset).name;
}

std::optional<Preset> parsePreset(std::string_view name) {
    for (const PresetPolicy& policy : presetPolicies) {
        if (policy.name == name) {
            return policy.preset;
        }
    }
    return std::nullopt;
}

bool WriterMetadata::empty() const {
    return name.empty() && !preset && !codec && !level && !chunkPolicy && !chunkSize && !workers &&
        !chunkMin && !chunkTarget && !chunkMax && !chunkAlgorithm;
}

WriterMetadata describeWriter(
    std::string_view name,
    const CompressionProfile& compression,
    ChunkPolicy policy,
    std::uint32_t chunkSize,
    const CdcParams& cdc,
    std::uint32_t workers
) {
    WriterMetadata metadata;
    metadata.name = name;
    if (compression.preset) {
        metadata.preset = static_cast<std::uint64_t>(*compression.preset);
    }
    metadata.codec = static_cast<std::uint64_t>(compression.codec);
    metadata.level = compression.level;
    metadata.chunkPolicy = static_cast<std::uint64_t>(policy);
    metadata.chunkSize = chunkSize;
    metadata.workers = workers;

    if (policy == ChunkPolicy::Cdc) {
        metadata.chunkMin = cdc.min;
        metadata.chunkTarget = cdc.target;
        metadata.chunkMax = cdc.max;
        metadata.chunkAlgorithm = static_cast<std::uint64_t>(CdcAlgorithm::Gear);
    }
    return metadata;
}

WriterMetadata describeWriter(
    std::string_view name,
    const CompressionProfile& compression,
    std::uint32_t chunkSize,
    std::uint32_t workers
) {
    return describeWriter(
        name,
        compression,
        ChunkPolicy::Fixed,
        chunkSize,
        defaultCdcParams,
        workers
    );
}

Result<void> encodeWriterMetadata(
    const WriterMetadata& metadata,
    std::uint32_t number,
    TlvWriter& writer,
    std::vector<std::byte>& scratch
) {
    if (metadata.empty()) {
        return {};
    }

    scratch.clear();
    TlvWriter nested(scratch);
    if (!metadata.name.empty()) {
        auto name = nested.bytes(nameField, Criticality::Noncritical, bytesOf(metadata.name));
        if (!name) {
            return name;
        }
    }

    auto preset = putUnsigned(nested, presetField, metadata.preset);
    if (!preset) {
        return preset;
    }
    auto codec = putUnsigned(nested, codecField, metadata.codec);
    if (!codec) {
        return codec;
    }
    if (metadata.level) {
        auto level = nested.signed64(levelField, Criticality::Noncritical, *metadata.level);
        if (!level) {
            return level;
        }
    }
    auto policy = putUnsigned(nested, chunkPolicyField, metadata.chunkPolicy);
    if (!policy) {
        return policy;
    }
    auto size = putUnsigned(nested, chunkSizeField, metadata.chunkSize);
    if (!size) {
        return size;
    }
    auto workers = putUnsigned(nested, workersField, metadata.workers);
    if (!workers) {
        return workers;
    }
    auto chunkMin = putUnsigned(nested, chunkMinField, metadata.chunkMin);
    if (!chunkMin) {
        return chunkMin;
    }
    auto chunkTarget = putUnsigned(nested, chunkTargetField, metadata.chunkTarget);
    if (!chunkTarget) {
        return chunkTarget;
    }
    auto chunkMax = putUnsigned(nested, chunkMaxField, metadata.chunkMax);
    if (!chunkMax) {
        return chunkMax;
    }
    auto chunkAlgorithm = putUnsigned(nested, chunkAlgorithmField, metadata.chunkAlgorithm);
    if (!chunkAlgorithm) {
        return chunkAlgorithm;
    }

    return writer.bytes(number, Criticality::Noncritical, scratch);
}

Result<WriterMetadata> decodeWriterMetadata(const TlvField& field) {
    WriterMetadata metadata;
    TlvReader reader(field.value, field.offset);
    TlvField nested;
    while (true) {
        auto more = reader.next(nested);
        if (!more) {
            return std::unexpected(more.error());
        }
        if (!*more) {
            break;
        }

        bool known = nested.number >= nameField && nested.number <= chunkAlgorithmField &&
            nested.number != reservedDictionaryField;
        if (!known) {
            auto skipped = skipUnknownField(nested);
            if (!skipped) {
                return std::unexpected(skipped.error());
            }
            continue;
        }

        auto criticality = requireCriticality(nested, Criticality::Noncritical);
        if (!criticality) {
            return std::unexpected(criticality.error());
        }

        if (nested.number == nameField) {
            metadata.name = std::string_view(
                reinterpret_cast<const char*>(nested.value.data()),
                nested.value.size()
            );
            continue;
        }
        if (nested.number == levelField) {
            auto level = decodeTlvSigned64(nested);
            if (!level) {
                return std::unexpected(level.error());
            }
            metadata.level = *level;
            continue;
        }

        auto value = decodeTlvUnsigned(nested);
        if (!value) {
            return std::unexpected(value.error());
        }
        switch (nested.number) {
        case presetField:
            metadata.preset = *value;
            break;
        case codecField:
            metadata.codec = *value;
            break;
        case chunkPolicyField:
            metadata.chunkPolicy = *value;
            break;
        case chunkSizeField:
            metadata.chunkSize = *value;
            break;
        case chunkMinField:
            metadata.chunkMin = *value;
            break;
        case chunkTargetField:
            metadata.chunkTarget = *value;
            break;
        case chunkMaxField:
            metadata.chunkMax = *value;
            break;
        case chunkAlgorithmField:
            metadata.chunkAlgorithm = *value;
            break;
        default:
            metadata.workers = *value;
            break;
        }
    }

    if (metadata.empty()) {
        return fail(ErrorKind::Malformed, "explicit empty writer metadata", field.offset);
    }
    return metadata;
}

}
