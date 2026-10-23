#include "formats/wim/metadata.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace bale::wim {

namespace {

inline constexpr std::size_t dentryFixedSize = 102;
inline constexpr std::size_t streamFixedSize = 38;
inline constexpr std::int64_t filetimePerSecond = 10000000;
inline constexpr std::int64_t filetimeEpochGap = 11644473600;

[[nodiscard]] Result<std::string>
convertName(const std::byte* units, std::size_t unitCount, std::uint64_t at, const Limits& limits) {
    std::string out;
    out.reserve(unitCount * 2);
    for (std::size_t index = 0; index < unitCount; ++index) {
        std::uint16_t unit = loadLe<std::uint16_t>(units + index * 2);
        if (unit == 0) {
            return fail(ErrorKind::Malformed, "WIM name contains NUL", at);
        }
        if (unit < 0x80) {
            out.push_back(static_cast<char>(unit));
        } else if (unit < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (unit >> 6)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        } else if (unit < 0xD800 || unit >= 0xE000) {
            out.push_back(static_cast<char>(0xE0 | (unit >> 12)));
            out.push_back(static_cast<char>(0x80 | ((unit >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (unit & 0x3F)));
        } else {
            ++index;
            if (index >= unitCount) {
                return fail(ErrorKind::Malformed, "WIM name ends inside a surrogate pair", at);
            }
            std::uint16_t low = loadLe<std::uint16_t>(units + index * 2);
            if (low < 0xDC00 || low >= 0xE000) {
                return fail(ErrorKind::Malformed, "WIM name has a lone surrogate", at);
            }
            char32_t point =
                (static_cast<char32_t>(unit - 0xD800) << 10) + (low - 0xDC00) + 0x10000;
            out.push_back(static_cast<char>(0xF0 | (point >> 18)));
            out.push_back(static_cast<char>(0x80 | ((point >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (point & 0x3F)));
        }
        if (out.size() > limits.maxNameBytes * 4) {
            return fail(ErrorKind::LimitExceeded, "WIM name exceeds limit", at);
        }
    }
    return out;
}

[[nodiscard]] std::int64_t filetimeToUnix(std::uint64_t filetime) {
    auto seconds = static_cast<std::int64_t>(filetime / filetimePerSecond);
    return seconds - filetimeEpochGap;
}

[[nodiscard]] std::uint32_t modeFor(std::uint32_t attributes) {
    std::uint32_t mode = (attributes & attrDirectory) != 0 ? 040755U : 0100644U;
    if ((attributes & attrReadOnly) != 0) {
        mode &= ~static_cast<std::uint32_t>(0222);
    }
    return mode;
}

struct DentryView {
    std::uint64_t at = 0;
    std::uint64_t length = 0;
    std::uint32_t attributes = 0;
    std::uint64_t subdir = 0;
    std::int64_t mtime = 0;
    std::array<std::byte, hashSize> mainHash{};
    std::uint32_t reparseTag = 0;
    std::uint64_t group = 0;
    bool reparse = false;
    std::uint16_t extraStreams = 0;
    std::string name;
    std::size_t streamsAt = 0;
};

struct StreamView {
    std::array<std::byte, hashSize> hash{};
    std::string streamName;
    bool named = false;
};

[[nodiscard]] Result<DentryView> parseDentry(
    const std::vector<std::byte>& buffer,
    std::uint64_t at,
    bool isRoot,
    const Limits& limits
) {
    auto end = checkedAdd(at, dentryFixedSize);
    if (!end || *end > buffer.size()) {
        return fail(ErrorKind::Truncated, "WIM ends inside a directory entry", at);
    }
    const std::byte* raw = buffer.data() + at;
    std::uint64_t length = loadLe<std::uint64_t>(raw);
    if (length <= 8) {
        return fail(ErrorKind::Malformed, "WIM directory entry length is invalid", at);
    }
    length = (length + 7) & ~std::uint64_t{7};
    if (length < dentryFixedSize) {
        return fail(ErrorKind::Malformed, "WIM directory entry is too short", at);
    }
    auto bound = checkedAdd(at, length);
    if (!bound || *bound > buffer.size()) {
        return fail(ErrorKind::Truncated, "WIM ends inside a directory entry", at);
    }

    DentryView view;
    view.at = at;
    view.length = length;
    view.attributes = loadLe<std::uint32_t>(raw + 8);
    view.subdir = loadLe<std::uint64_t>(raw + 16);
    view.mtime = filetimeToUnix(loadLe<std::uint64_t>(raw + 56));
    for (std::size_t index = 0; index < hashSize; ++index) {
        view.mainHash[index] = raw[64 + index];
    }
    view.reparse = (view.attributes & attrReparse) != 0;
    if (view.reparse) {
        view.reparseTag = loadLe<std::uint32_t>(raw + 88);
    } else {
        view.group = loadLe<std::uint64_t>(raw + 88);
    }
    view.extraStreams = loadLe<std::uint16_t>(raw + 96);
    std::uint16_t shortBytes = loadLe<std::uint16_t>(raw + 98);
    std::uint16_t nameBytes = loadLe<std::uint16_t>(raw + 100);
    if ((shortBytes & 1) != 0 || (nameBytes & 1) != 0) {
        return fail(ErrorKind::Malformed, "WIM name length is odd", at);
    }

    std::uint64_t cursor = at + dentryFixedSize;
    if (nameBytes > 0) {
        auto nameEnd = checkedAdd(cursor, static_cast<std::uint64_t>(nameBytes));
        auto nullEnd = nameEnd ? checkedAdd(*nameEnd, std::uint64_t{2}) : std::nullopt;
        if (!nullEnd || *nullEnd > at + length) {
            return fail(ErrorKind::Malformed, "WIM name runs past its entry", at);
        }
        auto name = convertName(buffer.data() + cursor, nameBytes / 2, at, limits);
        if (!name) {
            return tl::unexpected<Error>(name.error());
        }
        if (name->empty() || name->size() > limits.maxNameBytes) {
            return fail(ErrorKind::Malformed, "WIM entry without a name", at);
        }
        view.name = std::move(*name);
        cursor = *nullEnd;
    } else if (!isRoot) {
        return fail(ErrorKind::Malformed, "WIM entry without a name", at);
    }
    if (shortBytes > 0) {
        auto shortEnd = checkedAdd(cursor, static_cast<std::uint64_t>(shortBytes));
        auto nullEnd = shortEnd ? checkedAdd(*shortEnd, std::uint64_t{2}) : std::nullopt;
        if (!nullEnd || *nullEnd > at + length) {
            return fail(ErrorKind::Malformed, "WIM short name runs past its entry", at);
        }
        cursor = *nullEnd;
    }
    cursor = (cursor + 7) & ~std::uint64_t{7};
    if (cursor > at + length) {
        return fail(ErrorKind::Malformed, "WIM entry names run past its entry", at);
    }
    view.streamsAt = static_cast<std::size_t>(at + length);
    return view;
}

[[nodiscard]] Result<StreamView>
parseStream(const std::vector<std::byte>& buffer, std::uint64_t at, const Limits& limits) {
    auto end = checkedAdd(at, streamFixedSize);
    if (!end || *end > buffer.size()) {
        return fail(ErrorKind::Truncated, "WIM ends inside a stream entry", at);
    }
    const std::byte* raw = buffer.data() + at;
    std::uint64_t length = loadLe<std::uint64_t>(raw);
    length = (length + 7) & ~std::uint64_t{7};
    if (length < streamFixedSize) {
        return fail(ErrorKind::Malformed, "WIM stream entry is too short", at);
    }
    auto bound = checkedAdd(at, length);
    if (!bound || *bound > buffer.size()) {
        return fail(ErrorKind::Truncated, "WIM ends inside a stream entry", at);
    }
    StreamView view;
    for (std::size_t index = 0; index < hashSize; ++index) {
        view.hash[index] = raw[16 + index];
    }
    std::uint16_t nameBytes = loadLe<std::uint16_t>(raw + 36);
    if ((nameBytes & 1) != 0) {
        return fail(ErrorKind::Malformed, "WIM stream name length is odd", at);
    }
    if (nameBytes > 0) {
        auto nameEnd = checkedAdd(at + streamFixedSize, static_cast<std::uint64_t>(nameBytes));
        auto nullEnd = nameEnd ? checkedAdd(*nameEnd, std::uint64_t{2}) : std::nullopt;
        if (!nullEnd || *nullEnd > at + length) {
            return fail(ErrorKind::Malformed, "WIM stream name runs past its entry", at);
        }
        auto name = convertName(buffer.data() + at + streamFixedSize, nameBytes / 2, at, limits);
        if (!name) {
            return tl::unexpected<Error>(name.error());
        }
        view.streamName = std::move(*name);
        view.named = true;
    }
    return view;
}

[[nodiscard]] bool isZeroHash(const std::array<std::byte, hashSize>& hash) {
    for (std::byte unit : hash) {
        if (unit != std::byte{0}) {
            return false;
        }
    }
    return true;
}

}

Result<std::string> parseReparseTarget(std::span<const std::byte> data, std::uint32_t tag) {
    bool symlink = tag == reparseTagSymlink;
    std::size_t base = symlink ? 12 : 8;
    if (data.size() < base + 4) {
        return fail(ErrorKind::Malformed, "WIM reparse buffer is too short");
    }
    std::uint16_t printOffset = loadLe<std::uint16_t>(data.data() + 4);
    std::uint16_t printLength = loadLe<std::uint16_t>(data.data() + 6);
    auto begin = checkedAdd(base, static_cast<std::size_t>(printOffset));
    auto end = begin ? checkedAdd(*begin, static_cast<std::size_t>(printLength)) : std::nullopt;
    if (!end || *end > data.size() || (printLength & 1) != 0) {
        return fail(ErrorKind::Malformed, "WIM reparse target is out of range");
    }
    Limits widen;
    widen.maxNameBytes = 32768;
    auto target = convertName(data.data() + *begin, printLength / 2, Error::noOffset, widen);
    if (!target) {
        return tl::unexpected<Error>(target.error());
    }
    constexpr std::string_view prefix = "\\??\\";
    if (target->starts_with(prefix)) {
        target->erase(0, prefix.size());
    }
    for (char& unit : *target) {
        if (unit == '\\') {
            unit = '/';
        }
    }
    return *target;
}

Result<std::vector<Node>> walkMetadata(const Resource& meta, const Limits& limits) {
    if (meta.isEmpty()) {
        return fail(ErrorKind::Malformed, "WIM image metadata is missing");
    }
    if (meta.uncompressedSize() > limits.maxTotalBytes) {
        return fail(ErrorKind::LimitExceeded, "WIM image metadata exceeds limit");
    }
    std::size_t bytes = static_cast<std::size_t>(meta.uncompressedSize());
    std::vector<std::byte> buffer(bytes);
    auto sink = [&buffer,
                 at = std::size_t{0}](std::span<const std::byte> chunk) mutable -> Result<void> {
        if (chunk.size() > buffer.size() - at) {
            return fail(ErrorKind::Malformed, "WIM metadata overflows its buffer");
        }
        std::copy(chunk.begin(), chunk.end(), buffer.begin() + static_cast<std::ptrdiff_t>(at));
        at += chunk.size();
        return Result<void>{};
    };
    std::vector<std::byte> scratch(65536);
    auto streamed = meta.streamRange(0, meta.uncompressedSize(), scratch, sink);
    if (!streamed) {
        return tl::unexpected<Error>(streamed.error());
    }

    if (buffer.size() < 8) {
        return fail(ErrorKind::Truncated, "WIM ends inside its security data");
    }
    std::uint32_t securityTotal = loadLe<std::uint32_t>(buffer.data());
    std::uint32_t securityCount = loadLe<std::uint32_t>(buffer.data() + 4);
    std::uint64_t securityLength = securityTotal == 0 ? 8 : (securityTotal + 7) & ~7U;
    if (securityCount > 0x80000000U) {
        return fail(ErrorKind::Malformed, "WIM security descriptor count is invalid");
    }
    auto sizesEnd = checkedAdd(std::uint64_t{8}, static_cast<std::uint64_t>(securityCount) * 8);
    if (!sizesEnd || *sizesEnd > securityLength || securityLength > buffer.size()) {
        return fail(ErrorKind::Malformed, "WIM security data is out of range");
    }

    std::vector<Node> nodes;
    std::unordered_map<std::uint64_t, std::size_t> hardlinks;
    std::unordered_set<std::uint64_t> visited;

    auto rootEnd = checkedAdd(securityLength, std::uint64_t{8});
    if (!rootEnd || *rootEnd > buffer.size()) {
        return fail(ErrorKind::Truncated, "WIM ends inside its root entry");
    }
    if (loadLe<std::uint64_t>(buffer.data() + securityLength) <= 8) {
        return nodes;
    }
    auto root = parseDentry(buffer, securityLength, true, limits);
    if (!root) {
        return tl::unexpected<Error>(root.error());
    }
    if (root->subdir == 0) {
        return nodes;
    }
    if (root->subdir >= buffer.size()) {
        return fail(ErrorKind::Malformed, "WIM subdirectory is out of range");
    }
    visited.insert(root->subdir);

    struct Frame {
        std::uint64_t offset = 0;
        std::string prefix;
        std::uint32_t depth = 0;
    };
    std::vector<Frame> stack{{root->subdir, {}, 1}};

    while (!stack.empty()) {
        Frame frame = std::move(stack.back());
        stack.pop_back();
        if (frame.depth > limits.maxDepth) {
            return fail(ErrorKind::LimitExceeded, "WIM directory depth exceeds limit");
        }
        std::uint64_t at = frame.offset;
        while (true) {
            auto lengthEnd = checkedAdd(at, std::uint64_t{8});
            if (!lengthEnd || *lengthEnd > buffer.size()) {
                return fail(ErrorKind::Truncated, "WIM ends inside a directory", at);
            }
            std::uint64_t rawLength = loadLe<std::uint64_t>(buffer.data() + at);
            if (rawLength <= 8) {
                break;
            }
            auto entry = parseDentry(buffer, at, false, limits);
            if (!entry) {
                return tl::unexpected<Error>(entry.error());
            }

            std::string path =
                frame.prefix.empty() ? entry->name : frame.prefix + '/' + entry->name;

            Node node;
            node.path = path;
            node.mtimeSeconds = entry->mtime;
            node.mode = modeFor(entry->attributes);

            std::vector<StreamView> extras;
            std::uint64_t streamAt = entry->streamsAt;
            for (std::uint16_t index = 0; index < entry->extraStreams; ++index) {
                auto stream = parseStream(buffer, streamAt, limits);
                if (!stream) {
                    return tl::unexpected<Error>(stream.error());
                }
                auto length = loadLe<std::uint64_t>(buffer.data() + streamAt);
                length = (length + 7) & ~std::uint64_t{7};
                auto next = checkedAdd(streamAt, length);
                if (!next || *next > buffer.size()) {
                    return fail(ErrorKind::Truncated, "WIM ends inside its streams", entry->at);
                }
                streamAt = *next;
                extras.push_back(std::move(*stream));
            }
            // NOTE: sibling records resume after the extra stream entries,
            // which follow the dentry but are not covered by its length.
            at = streamAt;

            bool encrypted = (entry->attributes & attrEncrypted) != 0;
            bool directory = (entry->attributes & attrDirectory) != 0;
            if (entry->reparse) {
                if (entry->reparseTag == reparseTagSymlink ||
                    entry->reparseTag == reparseTagJunction) {
                    node.kind = EntryKind::Symlink;
                    node.reparseTag = entry->reparseTag;
                } else {
                    node.kind = EntryKind::Other;
                }
            } else if (directory) {
                node.kind = EntryKind::Directory;
            } else if (encrypted) {
                node.kind = EntryKind::Other;
            }

            bool unnamedExtra = false;
            for (const StreamView& stream : extras) {
                if (!stream.named) {
                    unnamedExtra = true;
                }
            }
            bool foundData = false;
            bool foundReparse = false;
            auto consider = [&](const std::array<std::byte, hashSize>& hash) {
                if (node.kind == EntryKind::Symlink && !foundReparse) {
                    node.reparseHash = hash;
                    node.hasReparse = !isZeroHash(hash);
                    foundReparse = true;
                    return;
                }
                if (!foundData) {
                    node.hash = hash;
                    node.hasData = !isZeroHash(hash);
                    foundData = true;
                }
            };
            if (!isZeroHash(entry->mainHash) || !unnamedExtra) {
                consider(entry->mainHash);
            }
            for (const StreamView& stream : extras) {
                if (stream.named) {
                    continue;
                }
                consider(stream.hash);
            }
            if (!foundData && !foundReparse) {
                if (node.kind == EntryKind::Symlink) {
                    node.hasReparse = false;
                } else if (!directory) {
                    node.hash = entry->mainHash;
                    node.hasData = false;
                }
            }
            if (node.kind == EntryKind::Symlink && node.hasReparse) {
                node.hasData = false;
            }

            for (const StreamView& stream : extras) {
                if (!stream.named) {
                    continue;
                }
                Node alternate;
                alternate.path = path + ':' + stream.streamName;
                alternate.mtimeSeconds = node.mtimeSeconds;
                alternate.mode = node.mode;
                alternate.kind = EntryKind::AlternateStream;
                alternate.hash = stream.hash;
                alternate.hasData = !isZeroHash(stream.hash);
                if (nodes.size() >= limits.maxEntries) {
                    return fail(ErrorKind::LimitExceeded, "WIM entry count exceeds limit");
                }
                nodes.push_back(std::move(alternate));
            }

            if (path.empty()) {
                return fail(ErrorKind::Malformed, "WIM entry without a name", entry->at);
            }
            if (!entry->reparse && !directory && !encrypted && entry->group != 0) {
                auto known = hardlinks.find(entry->group);
                if (known != hardlinks.end() && nodes[known->second].hash == node.hash) {
                    node.kind = EntryKind::HardLink;
                    node.linkTarget = nodes[known->second].path;
                    node.hasData = false;
                } else if (known == hardlinks.end()) {
                    hardlinks[entry->group] = nodes.size();
                }
            }

            bool pushChildren =
                directory && entry->subdir != 0 && node.kind == EntryKind::Directory;
            if (nodes.size() >= limits.maxEntries) {
                return fail(ErrorKind::LimitExceeded, "WIM entry count exceeds limit");
            }
            nodes.push_back(std::move(node));
            if (pushChildren) {
                if (entry->subdir >= buffer.size()) {
                    return fail(ErrorKind::Malformed, "WIM subdirectory is out of range");
                }
                if (!visited.insert(entry->subdir).second) {
                    return fail(ErrorKind::Malformed, "WIM directory structure loops", entry->at);
                }
                stack.push_back({entry->subdir, std::move(path), frame.depth + 1});
            }
        }
    }
    return nodes;
}

}
