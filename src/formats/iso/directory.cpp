#include "formats/iso/directory.hpp"

#include "formats/iso/susp.hpp"

#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace bale::iso {

namespace {

constexpr std::size_t minRecordSize = 33;
constexpr std::size_t extentOffset = 2;
constexpr std::size_t sizeOffset = 10;
constexpr std::size_t dateOffset = 18;
constexpr std::size_t dateLength = 7;
constexpr std::size_t flagsOffset = 25;
constexpr std::size_t unitOffset = 26;
constexpr std::size_t gapOffset = 27;
constexpr std::size_t volumeSequenceOffset = 28;
constexpr std::size_t nameLengthOffset = 32;
constexpr std::size_t nameOffset = 33;

constexpr std::uint8_t flagDirectory = 0x02;
constexpr std::uint8_t flagAssociated = 0x04;
constexpr std::uint8_t flagMultiExtent = 0x80;

constexpr std::uint16_t fileTypeMask = 0170000;
constexpr std::uint16_t symlinkType = 0120000;
constexpr std::uint16_t charType = 0020000;
constexpr std::uint16_t blockType = 0060000;
constexpr std::uint16_t fifoType = 0010000;
constexpr std::uint16_t socketType = 0140000;

constexpr std::uint32_t defaultFileMode = 0100444;
constexpr std::uint32_t defaultDirectoryMode = 0040555;

[[nodiscard]] Result<std::string>
decodeJolietName(std::span<const std::byte> raw, const Limits& limits, std::uint64_t recordOffset) {
    if (raw.size() % 2 != 0) {
        return fail(ErrorKind::Malformed, "Joliet name with an odd length", recordOffset);
    }
    std::string text;
    text.reserve(raw.size());
    for (std::size_t at = 0; at < raw.size(); at += 2) {
        auto unit = static_cast<std::uint16_t>(
            (static_cast<unsigned>(raw[at]) << 8) | static_cast<unsigned>(raw[at + 1])
        );
        if (unit < 0x80) {
            if (unit == 0) {
                return fail(ErrorKind::Malformed, "Joliet name contains NUL", recordOffset);
            }
            text.push_back(static_cast<char>(unit));
        } else if (unit < 0x800) {
            text.push_back(static_cast<char>(0xC0 | (unit >> 6)));
            text.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        } else if (unit < 0xD800 || unit >= 0xE000) {
            text.push_back(static_cast<char>(0xE0 | (unit >> 12)));
            text.push_back(static_cast<char>(0x80 | ((unit >> 6) & 0x3F)));
            text.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        } else {
            return fail(ErrorKind::Malformed, "invalid Joliet name", recordOffset);
        }
    }
    if (text.find('/') != std::string::npos) {
        return fail(ErrorKind::Malformed, "Joliet name contains a slash", recordOffset);
    }
    auto stripped = stripVersionSuffix(text);
    if (stripped.empty()) {
        return fail(ErrorKind::Malformed, "entry without a name", recordOffset);
    }
    if (stripped.size() > limits.maxNameBytes) {
        return fail(ErrorKind::LimitExceeded, "entry name exceeds limit", recordOffset);
    }
    return std::string(stripped);
}

struct RawRecord {
    std::uint32_t extent = 0;
    std::uint64_t size = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint8_t flags = 0;
    std::string_view nameBytes;
    std::span<const std::byte> systemUse;
};

[[nodiscard]] Result<RawRecord>
parseRecord(std::span<const std::byte> data, std::size_t at, std::uint64_t baseOffset) {
    auto recordOffset = baseOffset + static_cast<std::uint64_t>(at);
    std::size_t length = static_cast<std::size_t>(static_cast<std::uint8_t>(data[at]));
    if (length < minRecordSize || at + length > data.size()) {
        return fail(ErrorKind::Malformed, "bad ISO directory record", recordOffset);
    }
    auto body = data.subspan(at, length);

    if (body[1] != std::byte{0}) {
        return fail(
            ErrorKind::Unsupported,
            "ISO extended attributes are not supported",
            recordOffset
        );
    }
    auto extent = bothLe32(body.subspan(extentOffset, 8));
    if (!extent) {
        return fail(ErrorKind::Malformed, "ISO extent is not both-endian", recordOffset);
    }
    if (*extent < systemSectors) {
        return fail(ErrorKind::Malformed, "ISO extent points into the system area", recordOffset);
    }
    auto size = bothLe32(body.subspan(sizeOffset, 8));
    if (!size) {
        return fail(ErrorKind::Malformed, "ISO data length is not both-endian", recordOffset);
    }
    auto mtime = shortTimeToUnix(body.subspan(dateOffset, dateLength));
    if (!mtime) {
        return fail(ErrorKind::Malformed, "ISO timestamp out of range", recordOffset);
    }

    std::uint8_t flags = static_cast<std::uint8_t>(body[flagsOffset]);
    if (body[unitOffset] != std::byte{0} || body[gapOffset] != std::byte{0}) {
        return fail(
            ErrorKind::Unsupported,
            "interleaved ISO extents are not supported",
            recordOffset
        );
    }
    if ((flags & flagAssociated) != 0) {
        return fail(ErrorKind::Unsupported, "associated ISO files are not supported", recordOffset);
    }
    std::uint16_t littleSequence = readLe16(body.subspan(volumeSequenceOffset, 2));
    auto sequenceBytes = body.subspan(volumeSequenceOffset + 2, 2);
    std::uint16_t bigSequence = static_cast<std::uint16_t>(
        (static_cast<unsigned>(sequenceBytes[0]) << 8) | static_cast<unsigned>(sequenceBytes[1])
    );
    if (littleSequence != bigSequence) {
        return fail(ErrorKind::Malformed, "ISO volume sequence is not both-endian", recordOffset);
    }
    if (littleSequence != 1) {
        return fail(
            ErrorKind::Unsupported,
            "multi-volume ISO sets are not supported",
            recordOffset
        );
    }

    std::size_t nameLength =
        static_cast<std::size_t>(static_cast<std::uint8_t>(body[nameLengthOffset]));
    if (nameOffset + nameLength > length) {
        return fail(ErrorKind::Malformed, "ISO name runs past its record", recordOffset);
    }
    std::size_t systemStart = nameOffset + nameLength;
    if (systemStart < length && (systemStart % 2) != 0) {
        ++systemStart;
        if (systemStart > length) {
            return fail(
                ErrorKind::Malformed,
                "ISO name padding runs past its record",
                recordOffset
            );
        }
    }

    RawRecord record;
    record.extent = *extent;
    record.size = *size;
    record.mtimeSeconds = *mtime;
    record.flags = flags;
    record.nameBytes =
        std::string_view(reinterpret_cast<const char*>(body.data() + nameOffset), nameLength);
    record.systemUse = body.subspan(systemStart, length - systemStart);
    return record;
}

[[nodiscard]] bool isDotName(std::string_view name) {
    return name.size() == 1 && (name[0] == '\0' || name[0] == '\x01');
}

[[nodiscard]] Result<std::vector<std::byte>> readExtents(
    const File& file,
    std::uint64_t fileSize,
    std::span<const Extent> extents,
    const Limits& limits
) {
    std::uint64_t total = 0;
    for (const Extent& extent : extents) {
        auto next = checkedAdd(total, extent.length);
        if (!next) {
            return fail(ErrorKind::Malformed, "ISO directory size overflows");
        }
        total = *next;
    }
    if (total > limits.maxDirectoryBytes) {
        return fail(ErrorKind::LimitExceeded, "ISO directory exceeds limit");
    }
    auto bytes = checkedCast<std::size_t>(total);
    if (!bytes) {
        return fail(ErrorKind::LimitExceeded, "ISO directory exceeds limit");
    }

    std::vector<std::byte> data(*bytes);
    std::size_t at = 0;
    for (const Extent& extent : extents) {
        auto end = checkedAdd(extent.offset, extent.length);
        if (!end || *end > fileSize) {
            return fail(ErrorKind::Truncated, "ISO directory extends past end of file");
        }
        auto chunk = std::span(data).subspan(at, static_cast<std::size_t>(extent.length));
        auto read = file.readExactAt(extent.offset, chunk);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        at += static_cast<std::size_t>(extent.length);
    }
    return data;
}

struct PendingDir {
    std::string path;
    std::uint32_t depth = 0;
    std::vector<Extent> extents;
};

struct PendingFile {
    std::size_t index = 0;
    std::uint64_t at = 0;
};

}

Result<std::vector<Node>> walkTree(
    const File& file,
    std::uint64_t fileSize,
    std::uint32_t rootExtent,
    std::uint64_t rootSize,
    bool joliet,
    const Limits& limits,
    bool& sawRockRidge
) {
    auto rootStart = sectorOffset(rootExtent, Error::noOffset);
    if (!rootStart) {
        return tl::unexpected<Error>(rootStart.error());
    }

    std::vector<Node> nodes;
    std::unordered_set<std::string> seen;
    std::vector<PendingDir> queue;
    queue.push_back(
        PendingDir{
            .path = {},
            .depth = 0,
            .extents = {Extent{.offset = *rootStart, .length = rootSize}},
        }
    );
    sawRockRidge = false;
    std::uint64_t totalBytes = 0;

    for (std::size_t head = 0; head < queue.size(); ++head) {
        PendingDir& current = queue[head];
        if (current.depth > limits.maxDepth) {
            return fail(ErrorKind::LimitExceeded, "ISO directory nesting exceeds limit");
        }
        auto loaded = readExtents(file, fileSize, current.extents, limits);
        if (!loaded) {
            return tl::unexpected<Error>(loaded.error());
        }
        std::vector<std::byte> data = std::move(*loaded);

        std::unordered_map<std::string, PendingFile> open;
        std::vector<std::size_t> freshDirs;
        std::uint64_t base = current.extents.empty() ? 0 : current.extents.front().offset;
        std::size_t at = 0;
        while (at < data.size()) {
            std::uint8_t recordLength = static_cast<std::uint8_t>(data[at]);
            if (recordLength == 0) {
                at = (at / sectorSize + 1) * sectorSize;
                continue;
            }
            auto parsed = parseRecord(data, at, base);
            if (!parsed) {
                return tl::unexpected<Error>(parsed.error());
            }
            auto recordOffset = base + static_cast<std::uint64_t>(at);
            at += recordLength;

            SuspState state;
            auto susp =
                parseSystemUse(parsed->systemUse, file, fileSize, limits, state, recordOffset, 0);
            if (!susp) {
                return tl::unexpected<Error>(susp.error());
            }
            if (state.sawRockRidge) {
                sawRockRidge = true;
            }
            if (state.relocated) {
                return fail(
                    ErrorKind::Unsupported,
                    "Rock Ridge relocation is not supported",
                    recordOffset
                );
            }
            if (state.namesDone && state.names.empty()) {
                return fail(ErrorKind::Malformed, "Rock Ridge name is empty", recordOffset);
            }
            if (!state.namesDone && !state.names.empty()) {
                return fail(ErrorKind::Malformed, "unterminated Rock Ridge name", recordOffset);
            }
            if (isDotName(parsed->nameBytes)) {
                continue;
            }

            std::string name;
            if (!state.names.empty()) {
                if (state.names.size() > limits.maxNameBytes) {
                    return fail(ErrorKind::LimitExceeded, "entry name exceeds limit", recordOffset);
                }
                name = state.names;
            } else if (joliet) {
                auto decoded = decodeJolietName(
                    std::as_bytes(
                        std::span<const char>(parsed->nameBytes.data(), parsed->nameBytes.size())
                    ),
                    limits,
                    recordOffset
                );
                if (!decoded) {
                    return tl::unexpected<Error>(decoded.error());
                }
                name = std::move(*decoded);
            } else {
                for (char byte : parsed->nameBytes) {
                    if (byte == '\0') {
                        return fail(ErrorKind::Malformed, "entry name contains NUL", recordOffset);
                    }
                    if (byte == '/') {
                        return fail(
                            ErrorKind::Malformed,
                            "entry name contains a slash",
                            recordOffset
                        );
                    }
                }
                auto stripped = stripVersionSuffix(
                    std::string_view(parsed->nameBytes.data(), parsed->nameBytes.size())
                );
                if (stripped.empty()) {
                    return fail(ErrorKind::Malformed, "entry without a name", recordOffset);
                }
                if (stripped.size() > limits.maxNameBytes) {
                    return fail(ErrorKind::LimitExceeded, "entry name exceeds limit", recordOffset);
                }
                name.assign(stripped);
            }

            std::string full = current.path.empty() ? name : current.path + '/' + name;
            if (full.size() > limits.maxPathBytes) {
                return fail(ErrorKind::LimitExceeded, "ISO path exceeds limit", recordOffset);
            }
            std::uint32_t depth = current.depth + 1;
            if (depth > limits.maxDepth) {
                return fail(
                    ErrorKind::LimitExceeded,
                    "ISO directory nesting exceeds limit",
                    recordOffset
                );
            }

            std::string target;
            if (!state.link.empty() || state.linkAbsolute) {
                target = state.linkAbsolute ? '/' + state.link : state.link;
                if ((parsed->flags & flagDirectory) != 0) {
                    return fail(ErrorKind::Malformed, "ISO symlink is a directory", recordOffset);
                }
                if (target.size() > limits.maxPathBytes) {
                    return fail(
                        ErrorKind::LimitExceeded,
                        "symlink target exceeds limit",
                        recordOffset
                    );
                }
            }

            EntryKind kind = EntryKind::Regular;
            bool symlink = !target.empty();
            if (symlink) {
                kind = EntryKind::Symlink;
            } else if ((parsed->flags & flagDirectory) != 0) {
                kind = EntryKind::Directory;
            } else if (state.hasMode) {
                if ((state.mode & fileTypeMask) == symlinkType) {
                    return fail(ErrorKind::Malformed, "ISO symlink without a target", recordOffset);
                }
                switch (state.mode & fileTypeMask) {
                case charType:
                    kind = EntryKind::CharDevice;
                    break;
                case blockType:
                    kind = EntryKind::BlockDevice;
                    break;
                case fifoType:
                    kind = EntryKind::Fifo;
                    break;
                case socketType:
                    kind = EntryKind::Socket;
                    break;
                default:
                    kind = EntryKind::Regular;
                    break;
                }
            }

            std::uint32_t mode = state.hasMode
                ? state.mode
                : (kind == EntryKind::Directory ? defaultDirectoryMode : defaultFileMode);
            std::int64_t mtime = state.hasStamp ? state.stampSeconds : parsed->mtimeSeconds;

            auto dataStart = sectorOffset(parsed->extent, recordOffset);
            if (!dataStart) {
                return tl::unexpected<Error>(dataStart.error());
            }
            auto dataEnd = checkedAdd(*dataStart, parsed->size);
            if (!dataEnd) {
                return fail(ErrorKind::Malformed, "ISO extent range overflows", recordOffset);
            }
            if (*dataEnd > fileSize) {
                return fail(
                    ErrorKind::Truncated,
                    "ISO extent extends past end of file",
                    recordOffset
                );
            }

            bool multi = (parsed->flags & flagMultiExtent) != 0;
            auto pending = open.find(full);
            if (pending != open.end()) {
                Node& node = nodes[pending->second.index];
                if (node.kind != kind) {
                    return fail(
                        ErrorKind::Malformed,
                        "multi-extent ISO entry changes kind",
                        recordOffset
                    );
                }
                auto grown = checkedAdd(node.size, parsed->size);
                if (!grown || *grown > limits.maxEntryBytes) {
                    return fail(ErrorKind::LimitExceeded, "entry exceeds size limit", recordOffset);
                }
                auto total = checkedAdd(totalBytes, parsed->size);
                if (!total || *total > limits.maxTotalBytes) {
                    return fail(ErrorKind::LimitExceeded, "total size exceeds limit", recordOffset);
                }
                totalBytes = *total;
                node.size = *grown;
                node.extents.push_back(Extent{.offset = *dataStart, .length = parsed->size});
                if (!multi) {
                    open.erase(pending);
                }
                continue;
            }
            if (seen.contains(full)) {
                continue;
            }
            if (nodes.size() >= limits.maxEntries) {
                return fail(ErrorKind::LimitExceeded, "entry count exceeds limit", recordOffset);
            }
            if (parsed->size > limits.maxEntryBytes) {
                return fail(ErrorKind::LimitExceeded, "entry exceeds size limit", recordOffset);
            }
            auto total = checkedAdd(totalBytes, parsed->size);
            if (!total || *total > limits.maxTotalBytes) {
                return fail(ErrorKind::LimitExceeded, "total size exceeds limit", recordOffset);
            }
            totalBytes = *total;

            std::size_t index = nodes.size();
            Node node;
            node.path = full;
            node.target = target;
            node.size = kind == EntryKind::Directory ? 0 : parsed->size;
            if (kind != EntryKind::Symlink && parsed->size > 0) {
                node.extents.push_back(Extent{.offset = *dataStart, .length = parsed->size});
            }
            node.mtimeSeconds = mtime;
            node.mode = mode;
            node.kind = kind;
            nodes.push_back(std::move(node));
            seen.insert(full);
            if (multi) {
                open.emplace(full, PendingFile{.index = index, .at = recordOffset});
            }
            if (kind == EntryKind::Directory && parsed->size > 0) {
                freshDirs.push_back(index);
            }
        }

        if (!open.empty()) {
            return fail(
                ErrorKind::Malformed,
                "unterminated multi-extent ISO entry",
                open.begin()->second.at
            );
        }
        for (std::size_t index : freshDirs) {
            queue.push_back(
                PendingDir{
                    .path = nodes[index].path,
                    .depth = current.depth + 1,
                    .extents = nodes[index].extents,
                }
            );
        }
    }
    return nodes;
}

}
