#include "archive/manifest.hpp"

#include "base/checked.hpp"
#include "format/tlv.hpp"
#include "security/archive_path.hpp"

#include <algorithm>
#include <limits>

namespace bale::archive {

namespace {

constexpr std::uint32_t versionField = 1;
constexpr std::uint32_t entriesField = 2;
constexpr std::uint32_t commentField = 3;
constexpr std::uint32_t writerField = 4;

constexpr std::uint32_t pathField = 1;
constexpr std::uint32_t kindField = 2;
constexpr std::uint32_t lengthField = 3;
constexpr std::uint32_t chunksField = 4;
constexpr std::uint32_t mtimeField = 5;
constexpr std::uint32_t modeField = 6;
constexpr std::uint32_t symlinkField = 9;
constexpr std::uint32_t hardLinkField = 10;

constexpr PathPolicy manifestPathPolicy{
    .backslash = Backslash::Reject,
    .syntax = PathSyntax::Strict,
    .windowsSafe = false,
    .allowRawNames = false,
};

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

std::string_view textOf(std::span<const std::byte> bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

Result<void> writeChunkList(
    TlvWriter& writer,
    const Manifest& manifest,
    const ManifestEntry& entry,
    std::vector<std::byte>& list,
    std::vector<std::byte>& element
) {
    auto chunks = manifest.chunksOf(entry);
    list.clear();
    appendLeb128(list, chunks.size());
    if (!manifest.encrypted()) {
        for (const auto& key : chunks) {
            element.clear();
            TlvWriter keyWriter(element);
            auto written = writeChunkKey(keyWriter, key);
            if (!written) {
                return written;
            }
            appendTlvListElement(list, element);
        }
        return writer.bytes(chunksField, Criticality::Critical, list);
    }
    auto objects = std::span(manifest.objectIds).subspan(entry.firstChunk, entry.chunkCount);
    for (std::size_t index = 0; index < chunks.size(); ++index) {
        element.clear();
        TlvWriter keyWriter(element);
        auto written = writeChunkKey(keyWriter, chunks[index]);
        if (!written) {
            return written;
        }
        auto object = keyWriter.bytes(10, Criticality::Critical, objects[index]);
        if (!object) {
            return object;
        }
        appendTlvListElement(list, element);
    }
    return writer.bytes(chunksField, Criticality::Critical, list);
}

Result<void> encodeEntry(
    const Manifest& manifest,
    const ManifestEntry& entry,
    std::vector<std::byte>& out,
    std::vector<std::byte>& list,
    std::vector<std::byte>& element
) {
    out.clear();
    TlvWriter writer(out);
    auto path = writer.bytes(pathField, Criticality::Critical, bytesOf(entry.path));
    if (!path) {
        return path;
    }

    auto kind = writer.unsignedValue(
        kindField,
        Criticality::Critical,
        static_cast<std::uint64_t>(entry.kind)
    );
    if (!kind) {
        return kind;
    }

    if (entry.kind == EntryKind::Regular) {
        auto length = writer.unsignedValue(lengthField, Criticality::Critical, entry.length);
        if (!length) {
            return length;
        }
        if (entry.chunkCount != 0) {
            auto chunks = writeChunkList(writer, manifest, entry, list, element);
            if (!chunks) {
                return chunks;
            }
        }
    }

    if (entry.mtimeNanoseconds) {
        auto mtime = writer.signed64(mtimeField, Criticality::Noncritical, *entry.mtimeNanoseconds);
        if (!mtime) {
            return mtime;
        }
    }
    if (entry.mode) {
        auto mode = writer.unsignedValue(modeField, Criticality::Noncritical, *entry.mode);
        if (!mode) {
            return mode;
        }
    }

    if (entry.kind == EntryKind::Symlink) {
        return writer.bytes(symlinkField, Criticality::Critical, bytesOf(entry.target));
    }
    if (entry.kind == EntryKind::HardLink) {
        return writer.bytes(hardLinkField, Criticality::Critical, bytesOf(entry.target));
    }
    return {};
}

struct RawEntry {
    std::span<const std::byte> path;
    std::span<const std::byte> symlink;
    std::span<const std::byte> hardLink;
    std::uint64_t kind = 0;
    std::uint64_t length = 0;
    std::uint64_t chunkCount = 0;
    std::optional<std::int64_t> mtime;
    std::optional<std::uint64_t> mode;
    bool hasPath = false;
    bool hasKind = false;
    bool hasLength = false;
    bool hasChunks = false;
    bool hasSymlink = false;
    bool hasHardLink = false;
};

constexpr Criticality criticalityOf(std::uint32_t number) {
    if (number == mtimeField || number == modeField) {
        return Criticality::Noncritical;
    }
    return Criticality::Critical;
}

constexpr bool isKnownEntryField(std::uint32_t number) {
    return (number >= pathField && number <= modeField) || number == symlinkField ||
        number == hardLinkField;
}

Result<void> readChunkList(
    const TlvField& field,
    std::uint64_t declaredLength,
    std::uint64_t& count,
    std::vector<ChunkKey>& chunks,
    std::vector<std::array<std::byte, 32>>& objectIds
) {
    auto list = TlvListReader::open(field, std::numeric_limits<std::uint32_t>::max());
    if (!list) {
        return tl::unexpected<Error>(list.error());
    }
    if (list->count() == 0) {
        return fail(ErrorKind::Malformed, "explicit empty chunk list", field.offset);
    }
    auto total = checkedAdd(chunks.size(), list->count());
    if (!total || *total > std::numeric_limits<std::uint32_t>::max()) {
        return fail(ErrorKind::LimitExceeded, "too many chunk references", field.offset);
    }

    std::uint64_t sum = 0;
    std::span<const std::byte> element;
    std::uint64_t elementOffset = 0;
    bool listEncrypted = !chunks.empty() && !objectIds.empty();
    bool listPlain = !listEncrypted && (chunks.empty() || objectIds.empty());
    // NOTE: detect per-list; first element decides, rest must match.
    bool decided = !chunks.empty() || !objectIds.empty();
    // NOTE: if this is the first chunk list in the manifest, decide from the first element.
    bool firstList = chunks.empty() && objectIds.empty();
    bool encrypted = false;
    bool sawFirst = false;
    while (true) {
        auto more = list->next(element, elementOffset);
        if (!more) {
            return tl::unexpected<Error>(more.error());
        }
        if (!*more) {
            break;
        }

        // NOTE: try encrypted extent first; plain keys lack field 10.
        bool hasObjectField = false;
        {
            TlvReader probe(element, elementOffset);
            TlvField probeField;
            while (true) {
                auto next = probe.next(probeField);
                if (!next) {
                    return tl::unexpected<Error>(next.error());
                }
                if (!*next) {
                    break;
                }
                if (probeField.number == 10) {
                    hasObjectField = true;
                    break;
                }
                if (probeField.number > 10) {
                    break;
                }
            }
        }
        if (!sawFirst) {
            encrypted = hasObjectField;
            sawFirst = true;
            if (firstList) {
                listEncrypted = encrypted;
                listPlain = !encrypted;
            } else if (encrypted != listEncrypted) {
                return fail(
                    ErrorKind::Malformed,
                    "mixed plain and encrypted chunk lists",
                    elementOffset
                );
            }
            (void)listPlain;
            (void)decided;
        } else if (hasObjectField != encrypted) {
            return fail(
                ErrorKind::Malformed,
                "mixed plain and encrypted chunk lists",
                elementOffset
            );
        }

        if (encrypted) {
            TlvReader reader(element, elementOffset);
            TlvField extentField;
            ChunkKeyFields keyFields;
            bool hasObject = false;
            std::array<std::byte, 32> object{};
            while (true) {
                auto next = reader.next(extentField);
                if (!next) {
                    return tl::unexpected<Error>(next.error());
                }
                if (!*next) {
                    break;
                }
                if (extentField.number == 10) {
                    auto critical = requireCriticality(extentField, Criticality::Critical);
                    if (!critical) {
                        return tl::unexpected<Error>(critical.error());
                    }
                    if (extentField.value.size() != 32) {
                        return fail(
                            ErrorKind::Malformed,
                            "object id has a bad size",
                            extentField.offset
                        );
                    }
                    std::ranges::copy(extentField.value, object.begin());
                    hasObject = true;
                    continue;
                }
                auto accepted = keyFields.accept(extentField);
                if (!accepted) {
                    return tl::unexpected<Error>(accepted.error());
                }
                if (*accepted) {
                    continue;
                }
                auto skipped = skipUnknownField(extentField);
                if (!skipped) {
                    return tl::unexpected<Error>(skipped.error());
                }
            }
            auto key = keyFields.finish(elementOffset);
            if (!key) {
                return tl::unexpected<Error>(key.error());
            }
            if (!hasObject) {
                return fail(
                    ErrorKind::Malformed,
                    "encrypted extent missing object id",
                    elementOffset
                );
            }
            auto next = checkedAdd(sum, key->length);
            if (!next || *next > declaredLength) {
                return fail(
                    ErrorKind::Malformed,
                    "chunk lengths exceed the file length",
                    elementOffset
                );
            }
            sum = *next;
            chunks.push_back(*key);
            objectIds.push_back(object);
        } else {
            auto key = decodeChunkKey(element, elementOffset);
            if (!key) {
                return tl::unexpected<Error>(key.error());
            }
            auto next = checkedAdd(sum, key->length);
            if (!next || *next > declaredLength) {
                return fail(
                    ErrorKind::Malformed,
                    "chunk lengths exceed the file length",
                    elementOffset
                );
            }
            sum = *next;
            chunks.push_back(*key);
        }
    }

    if (sum != declaredLength) {
        return fail(
            ErrorKind::Malformed,
            "chunk lengths do not add up to the file length",
            field.offset
        );
    }
    count = list->count();
    return {};
}

Result<RawEntry> readEntryFields(
    std::span<const std::byte> data,
    std::uint64_t offset,
    std::vector<ChunkKey>& chunks,
    std::vector<std::array<std::byte, 32>>& objectIds
) {
    RawEntry raw;
    TlvReader reader(data, offset);
    TlvField field;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return tl::unexpected<Error>(more.error());
        }
        if (!*more) {
            return raw;
        }

        if (!isKnownEntryField(field.number)) {
            auto skipped = skipUnknownField(field);
            if (!skipped) {
                return tl::unexpected<Error>(skipped.error());
            }
            continue;
        }

        auto critical = requireCriticality(field, criticalityOf(field.number));
        if (!critical) {
            return tl::unexpected<Error>(critical.error());
        }

        switch (field.number) {
        case pathField:
            raw.path = field.value;
            raw.hasPath = true;
            break;
        case kindField: {
            auto kind = decodeTlvUnsigned(field);
            if (!kind) {
                return tl::unexpected<Error>(kind.error());
            }
            raw.kind = *kind;
            raw.hasKind = true;
            break;
        }
        case lengthField: {
            auto length = decodeTlvUnsigned(field);
            if (!length) {
                return tl::unexpected<Error>(length.error());
            }
            raw.length = *length;
            raw.hasLength = true;
            break;
        }
        case chunksField: {
            if (!raw.hasLength) {
                return fail(ErrorKind::Malformed, "chunk list without a file length", field.offset);
            }
            auto read = readChunkList(field, raw.length, raw.chunkCount, chunks, objectIds);
            if (!read) {
                return tl::unexpected<Error>(read.error());
            }
            raw.hasChunks = true;
            break;
        }
        case mtimeField: {
            auto mtime = decodeTlvSigned64(field);
            if (!mtime) {
                return tl::unexpected<Error>(mtime.error());
            }
            raw.mtime = *mtime;
            break;
        }
        case modeField: {
            auto mode = decodeTlvUnsigned(field);
            if (!mode) {
                return tl::unexpected<Error>(mode.error());
            }
            raw.mode = *mode;
            break;
        }
        case symlinkField:
            raw.symlink = field.value;
            raw.hasSymlink = true;
            break;
        default:
            raw.hardLink = field.value;
            raw.hasHardLink = true;
            break;
        }
    }
}

Result<void> checkKindFields(const RawEntry& raw, std::uint64_t offset) {
    bool regular = raw.kind == static_cast<std::uint64_t>(EntryKind::Regular);
    bool symlink = raw.kind == static_cast<std::uint64_t>(EntryKind::Symlink);
    bool hardLink = raw.kind == static_cast<std::uint64_t>(EntryKind::HardLink);

    if (raw.hasLength != regular) {
        return fail(ErrorKind::Malformed, "file length present on the wrong entry kind", offset);
    }
    if (regular && raw.length != 0 && !raw.hasChunks) {
        return fail(ErrorKind::Malformed, "non-empty file without chunks", offset);
    }
    if (raw.hasSymlink != symlink) {
        return fail(ErrorKind::Malformed, "symlink target present on the wrong entry kind", offset);
    }
    if (raw.hasHardLink != hardLink) {
        return fail(
            ErrorKind::Malformed,
            "hard link target present on the wrong entry kind",
            offset
        );
    }
    if (raw.mode && (symlink || hardLink)) {
        return fail(ErrorKind::Malformed, "mode present on a link entry", offset);
    }
    if (raw.mtime && hardLink) {
        return fail(ErrorKind::Malformed, "modification time present on a hard link", offset);
    }
    if (raw.mode && *raw.mode > maxPermissionBits) {
        return fail(ErrorKind::Malformed, "mode has bits outside the permission bits", offset);
    }
    return {};
}

Result<std::string_view> checkedPath(
    std::span<const std::byte> raw,
    const Limits& limits,
    std::string& scratch,
    std::uint64_t offset
) {
    auto valid = validateEntryPath(textOf(raw), limits, scratch);
    if (!valid) {
        return fail(valid.error().kind, valid.error().what, offset);
    }
    return textOf(raw);
}

Result<ManifestEntry> decodeEntry(
    std::span<const std::byte> data,
    std::uint64_t offset,
    const Limits& limits,
    std::string& scratch,
    std::vector<ChunkKey>& chunks,
    std::vector<std::array<std::byte, 32>>& objectIds
) {
    std::size_t firstChunk = chunks.size();
    auto raw = readEntryFields(data, offset, chunks, objectIds);
    if (!raw) {
        return tl::unexpected<Error>(raw.error());
    }
    if (!raw->hasPath || !raw->hasKind) {
        return fail(ErrorKind::Malformed, "manifest entry without path or kind", offset);
    }
    if (raw->kind < static_cast<std::uint64_t>(EntryKind::Regular) ||
        raw->kind > static_cast<std::uint64_t>(EntryKind::HardLink)) {
        return fail(ErrorKind::Unsupported, "unknown manifest entry kind", offset);
    }

    auto kinds = checkKindFields(*raw, offset);
    if (!kinds) {
        return tl::unexpected<Error>(kinds.error());
    }

    auto path = checkedPath(raw->path, limits, scratch, offset);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    ManifestEntry entry;
    entry.path = *path;
    entry.kind = static_cast<EntryKind>(raw->kind);
    entry.length = raw->length;
    entry.mtimeNanoseconds = raw->mtime;
    if (raw->mode) {
        entry.mode = static_cast<std::uint32_t>(*raw->mode);
    }
    entry.firstChunk = static_cast<std::uint32_t>(firstChunk);
    entry.chunkCount = static_cast<std::uint32_t>(raw->chunkCount);

    if (raw->hasSymlink) {
        auto target = textOf(raw->symlink);
        if (target.empty() || target.size() > limits.maxPathBytes) {
            return fail(ErrorKind::Malformed, "symlink target empty or too long", offset);
        }
        if (target.find('\0') != std::string_view::npos) {
            return fail(ErrorKind::Malformed, "NUL byte in symlink target", offset);
        }
        entry.target = target;
    }
    if (raw->hasHardLink) {
        auto target = checkedPath(raw->hardLink, limits, scratch, offset);
        if (!target) {
            return tl::unexpected<Error>(target.error());
        }
        if (*target >= entry.path) {
            return fail(ErrorKind::Malformed, "hard link target does not precede the link", offset);
        }
        entry.target = *target;
    }
    return entry;
}

Result<void> checkTree(std::span<const ManifestEntry> entries, std::uint64_t offset) {
    for (const auto& entry : entries) {
        std::size_t slash = entry.path.find('/');
        while (slash != std::string_view::npos) {
            const auto* parent = findEntry(entries, entry.path.substr(0, slash));
            if (parent == nullptr || parent->kind != EntryKind::Directory) {
                return fail(
                    ErrorKind::Malformed,
                    "manifest entry without a parent directory entry",
                    offset
                );
            }
            slash = entry.path.find('/', slash + 1);
        }

        if (entry.kind != EntryKind::HardLink) {
            continue;
        }
        const auto* target = findEntry(entries, entry.target);
        if (target == nullptr || target->kind != EntryKind::Regular) {
            return fail(ErrorKind::Malformed, "hard link target is not a regular entry", offset);
        }
    }
    return {};
}

Result<void> decodeEntries(const TlvField& field, const Limits& limits, Manifest& out) {
    auto list = TlvListReader::open(field, limits.maxEntries);
    if (!list) {
        return tl::unexpected<Error>(list.error());
    }
    out.entries.reserve(static_cast<std::size_t>(list->count()));

    std::string scratch;
    std::span<const std::byte> element;
    std::uint64_t elementOffset = 0;
    while (true) {
        auto more = list->next(element, elementOffset);
        if (!more) {
            return tl::unexpected<Error>(more.error());
        }
        if (!*more) {
            break;
        }

        auto entry =
            decodeEntry(element, elementOffset, limits, scratch, out.chunks, out.objectIds);
        if (!entry) {
            return tl::unexpected<Error>(entry.error());
        }
        if (!out.entries.empty() && entry->path <= out.entries.back().path) {
            return fail(
                ErrorKind::Malformed,
                "manifest paths not in strictly increasing byte order",
                elementOffset
            );
        }
        out.entries.push_back(*entry);
    }
    return checkTree(out.entries, field.offset);
}

}

Result<void> encodeManifest(const Manifest& manifest, std::vector<std::byte>& out) {
    if (!manifest.objectIds.empty() && manifest.objectIds.size() != manifest.chunks.size()) {
        return fail(ErrorKind::Malformed, "encrypted manifest object count differs from chunks");
    }
    std::vector<std::byte> table;
    std::vector<std::byte> entry;
    std::vector<std::byte> list;
    std::vector<std::byte> element;

    appendLeb128(table, manifest.entries.size());
    for (const auto& item : manifest.entries) {
        auto encoded = encodeEntry(manifest, item, entry, list, element);
        if (!encoded) {
            return encoded;
        }
        appendTlvListElement(table, entry);
    }

    out.clear();
    TlvWriter writer(out);
    auto version = writer.unsignedValue(versionField, Criticality::Critical, manifestSchemaVersion);
    if (!version) {
        return version;
    }
    auto entries = writer.bytes(entriesField, Criticality::Critical, table);
    if (!entries) {
        return entries;
    }
    if (!manifest.comment.empty()) {
        auto comment =
            writer.bytes(commentField, Criticality::Noncritical, bytesOf(manifest.comment));
        if (!comment) {
            return comment;
        }
    }
    return encodeWriterMetadata(manifest.writer, writerField, writer, element);
}

Result<void> decodeManifest(
    std::span<const std::byte> payload,
    std::uint64_t offset,
    const Limits& limits,
    Manifest& out
) {
    out = Manifest{};
    TlvReader reader(payload, offset);
    TlvField field;
    bool hasVersion = false;
    bool hasEntries = false;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return tl::unexpected<Error>(more.error());
        }
        if (!*more) {
            break;
        }

        if (field.number > writerField) {
            auto skipped = skipUnknownField(field);
            if (!skipped) {
                return skipped;
            }
            continue;
        }

        bool critical = field.number == versionField || field.number == entriesField;
        auto criticality =
            requireCriticality(field, critical ? Criticality::Critical : Criticality::Noncritical);
        if (!criticality) {
            return criticality;
        }

        if (field.number == versionField) {
            auto version = decodeTlvUnsigned(field);
            if (!version) {
                return tl::unexpected<Error>(version.error());
            }
            if (*version != manifestSchemaVersion) {
                return fail(
                    ErrorKind::Unsupported,
                    "unsupported manifest schema version",
                    field.offset
                );
            }
            hasVersion = true;
            continue;
        }
        if (field.number == entriesField) {
            if (!hasVersion) {
                return fail(
                    ErrorKind::Malformed,
                    "manifest entries before schema version",
                    field.offset
                );
            }
            auto entries = decodeEntries(field, limits, out);
            if (!entries) {
                return entries;
            }
            hasEntries = true;
            continue;
        }

        if (field.value.empty()) {
            return fail(
                ErrorKind::Malformed,
                "explicit empty optional manifest field",
                field.offset
            );
        }
        if (field.number == commentField) {
            out.comment = textOf(field.value);
            continue;
        }

        auto metadata = decodeWriterMetadata(field);
        if (!metadata) {
            return tl::unexpected<Error>(metadata.error());
        }
        out.writer = *metadata;
    }

    if (!hasVersion || !hasEntries) {
        return fail(ErrorKind::Malformed, "manifest missing a required field", offset);
    }
    return {};
}

Result<void> validateEntryPath(std::string_view path, const Limits& limits, std::string& scratch) {
    auto normalized = normalizeArchivePath(bytesOf(path), manifestPathPolicy, limits, scratch);
    if (!normalized) {
        return tl::unexpected<Error>(normalized.error());
    }
    if (normalized->path != path) {
        return fail(ErrorKind::UnsafePath, "manifest path is not canonical");
    }
    return {};
}

const ManifestEntry* findEntry(std::span<const ManifestEntry> entries, std::string_view path) {
    auto found = std::ranges::lower_bound(entries, path, {}, &ManifestEntry::path);
    if (found == entries.end() || found->path != path) {
        return nullptr;
    }
    return &*found;
}

}
