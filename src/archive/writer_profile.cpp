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

struct PresetPolicy {
    Preset preset;
    std::string_view name;
    CodecId codec;
    std::int32_t level;
};

// TODO: replace these with choices measured by the codec benchmark (whitepaper 5.4.2); fast and
// restore-fast are LZ4 candidates once that codec exists.
constexpr std::array presetPolicies{
    PresetPolicy{
        .preset = Preset::Fast,
        .name = "fast",
        .codec = CodecId::Zstd,
        .level = 1,
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
        .codec = CodecId::Zstd,
        .level = 1,
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
    return name.empty() && !preset && !codec && !level && !chunkPolicy && !chunkSize && !workers;
}

WriterMetadata describeWriter(
    std::string_view name,
    const CompressionProfile& compression,
    std::uint32_t chunkSize
) {
    WriterMetadata metadata;
    metadata.name = name;
    if (compression.preset) {
        metadata.preset = static_cast<std::uint64_t>(*compression.preset);
    }
    metadata.codec = static_cast<std::uint64_t>(compression.codec);
    metadata.level = compression.level;
    metadata.chunkPolicy = static_cast<std::uint64_t>(ChunkPolicy::Fixed);
    metadata.chunkSize = chunkSize;
    metadata.workers = 1;
    return metadata;
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

        bool known = nested.number >= nameField && nested.number <= workersField &&
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
