#include "archive/index.hpp"

#include "base/checked.hpp"
#include "format/envelope.hpp"
#include "format/tlv.hpp"

#include <algorithm>
#include <limits>

namespace bale::archive {

namespace {

constexpr std::uint32_t versionField = 1;
constexpr std::uint32_t entriesField = 2;

constexpr std::uint32_t offsetField = 4;
constexpr std::uint32_t lengthField = 5;
constexpr std::uint32_t codecField = 6;

Result<IndexEntry> decodeEntry(std::span<const std::byte> data, std::uint64_t offset) {
    TlvReader reader(data, offset);
    ChunkKeyFields keyFields;
    TlvField field;
    IndexEntry entry;
    bool hasOffset = false;
    bool hasLength = false;
    bool hasCodec = false;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return std::unexpected(more.error());
        }
        if (!*more) {
            break;
        }

        auto accepted = keyFields.accept(field);
        if (!accepted) {
            return std::unexpected(accepted.error());
        }
        if (*accepted) {
            continue;
        }

        if (field.number > codecField) {
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
        auto value = decodeTlvUnsigned(field);
        if (!value) {
            return std::unexpected(value.error());
        }

        if (field.number == offsetField) {
            entry.recordOffset = *value;
            hasOffset = true;
        } else if (field.number == lengthField) {
            entry.recordLength = *value;
            hasLength = true;
        } else {
            if (*value > std::numeric_limits<std::uint32_t>::max()) {
                return fail(ErrorKind::Malformed, "codec ID exceeds 32 bits", field.offset);
            }
            entry.codec = static_cast<CodecId>(*value);
            hasCodec = true;
        }
    }

    auto key = keyFields.finish(offset);
    if (!key) {
        return std::unexpected(key.error());
    }
    if (!hasOffset || !hasLength || !hasCodec) {
        return fail(ErrorKind::Malformed, "index entry is missing a field", offset);
    }
    entry.key = *key;

    if (entry.recordOffset < superblockSize) {
        return fail(ErrorKind::Malformed, "index record offset inside superblock", offset);
    }
    if (entry.recordLength <= recordFramingSize) {
        return fail(ErrorKind::Malformed, "index record length too short", offset);
    }
    if (!checkedAdd(entry.recordOffset, entry.recordLength)) {
        return fail(ErrorKind::Malformed, "index record span overflows", offset);
    }
    return entry;
}

Result<void>
decodeEntries(const TlvField& field, std::uint64_t maxEntries, std::vector<IndexEntry>& out) {
    auto list = TlvListReader::open(field, maxEntries);
    if (!list) {
        return std::unexpected(list.error());
    }
    out.reserve(static_cast<std::size_t>(list->count()));

    std::span<const std::byte> element;
    std::uint64_t elementOffset = 0;
    while (true) {
        auto more = list->next(element, elementOffset);
        if (!more) {
            return std::unexpected(more.error());
        }
        if (!*more) {
            return {};
        }

        auto entry = decodeEntry(element, elementOffset);
        if (!entry) {
            return std::unexpected(entry.error());
        }
        if (!out.empty() && entry->key <= out.back().key) {
            return fail(
                ErrorKind::Malformed,
                "index keys not in strictly increasing order",
                elementOffset
            );
        }
        out.push_back(*entry);
    }
}

}

Result<void> encodeIndex(std::span<const IndexEntry> entries, std::vector<std::byte>& out) {
    std::vector<std::byte> table;
    std::vector<std::byte> element;
    appendLeb128(table, entries.size());
    for (const auto& entry : entries) {
        element.clear();
        TlvWriter writer(element);
        auto key = writeChunkKey(writer, entry.key);
        if (!key) {
            return key;
        }
        auto offset = writer.unsignedValue(offsetField, Criticality::Critical, entry.recordOffset);
        if (!offset) {
            return offset;
        }
        auto length = writer.unsignedValue(lengthField, Criticality::Critical, entry.recordLength);
        if (!length) {
            return length;
        }
        auto codec = writer.unsignedValue(
            codecField,
            Criticality::Critical,
            static_cast<std::uint64_t>(entry.codec)
        );
        if (!codec) {
            return codec;
        }
        appendTlvListElement(table, element);
    }

    out.clear();
    TlvWriter writer(out);
    auto version = writer.unsignedValue(versionField, Criticality::Critical, indexSchemaVersion);
    if (!version) {
        return version;
    }
    return writer.bytes(entriesField, Criticality::Critical, table);
}

Result<void> decodeIndex(
    std::span<const std::byte> payload,
    std::uint64_t offset,
    std::uint64_t maxEntries,
    std::vector<IndexEntry>& out
) {
    out.clear();
    TlvReader reader(payload, offset);
    TlvField field;
    bool hasVersion = false;
    bool hasEntries = false;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return std::unexpected(more.error());
        }
        if (!*more) {
            break;
        }

        if (field.number > entriesField) {
            auto skipped = skipUnknownField(field);
            if (!skipped) {
                return skipped;
            }
            continue;
        }

        auto critical = requireCriticality(field, Criticality::Critical);
        if (!critical) {
            return critical;
        }

        if (field.number == versionField) {
            auto version = decodeTlvUnsigned(field);
            if (!version) {
                return std::unexpected(version.error());
            }
            if (*version != indexSchemaVersion) {
                return fail(
                    ErrorKind::Unsupported,
                    "unsupported index schema version",
                    field.offset
                );
            }
            hasVersion = true;
            continue;
        }

        if (!hasVersion) {
            return fail(ErrorKind::Malformed, "index entries before schema version", field.offset);
        }
        auto entries = decodeEntries(field, maxEntries, out);
        if (!entries) {
            return entries;
        }
        hasEntries = true;
    }

    if (!hasVersion || !hasEntries) {
        return fail(ErrorKind::Malformed, "index missing a required field", offset);
    }
    return {};
}

const IndexEntry* findChunk(std::span<const IndexEntry> entries, const ChunkKey& key) {
    auto found = std::ranges::lower_bound(entries, key, {}, &IndexEntry::key);
    if (found == entries.end() || found->key != key) {
        return nullptr;
    }
    return &*found;
}

}
