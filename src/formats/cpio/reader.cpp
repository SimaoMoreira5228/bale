#include "formats/cpio/reader.hpp"

#include "base/checked.hpp"

#include <array>
#include <unordered_map>

namespace bale::cpio {

namespace {

Result<std::uint64_t> parseNamesize(std::span<const std::byte> header, std::uint64_t offset) {
    std::uint64_t value = 0;
    auto field = header.subspan(namesizeOffset, fieldLength);
    for (std::byte byte : field) {
        auto digit = static_cast<char>(byte);
        std::uint64_t nibble = 0;
        if (digit >= '0' && digit <= '9') {
            nibble = static_cast<std::uint64_t>(digit - '0');
        } else if (digit >= 'a' && digit <= 'f') {
            nibble = static_cast<std::uint64_t>(digit - 'a') + 10;
        } else if (digit >= 'A' && digit <= 'F') {
            nibble = static_cast<std::uint64_t>(digit - 'A') + 10;
        } else {
            return fail(ErrorKind::Malformed, "invalid cpio hex field", offset + namesizeOffset);
        }

        if (value > (0xFFFFFFFFFFFFFFFFULL >> 4)) {
            return fail(ErrorKind::Malformed, "cpio name size overflows", offset);
        }
        value = (value << 4) | nibble;
    }
    return value;
}

}

Result<Reader> Reader::open(File file, const Limits& limits) {
    auto size = file.size();
    if (!size) {
        return tl::unexpected<Error>(size.error());
    }
    if (*size < newcMagic.size()) {
        return fail(ErrorKind::Malformed, "not a cpio archive");
    }

    std::array<std::byte, newcMagic.size()> head{};
    auto read = file.readExactAt(0, head);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    if (!looksLikeCpio(head)) {
        return fail(ErrorKind::Malformed, "not a cpio archive");
    }

    Reader reader(std::move(file), limits);
    auto indexed = reader.index(*size);
    if (!indexed) {
        return tl::unexpected<Error>(indexed.error());
    }
    return reader;
}

Result<void> Reader::index(std::uint64_t fileSize) {
    auto offset = std::uint64_t{0};
    bool trailer = false;
    while (offset < fileSize) {
        if (entries_.size() >= limits_.maxEntries) {
            return fail(ErrorKind::LimitExceeded, "cpio entry count exceeds limit", offset);
        }

        auto done = indexOne(offset, fileSize);
        if (!done) {
            return tl::unexpected<Error>(done.error());
        }
        if (*done) {
            trailer = true;
            break;
        }
    }

    if (!trailer) {
        return fail(ErrorKind::Truncated, "cpio archive ends without a trailer", offset);
    }

    while (offset < fileSize) {
        std::array<std::byte, 512> tail{};
        auto tailLeft = fileSize - offset;
        auto want = tailLeft < tail.size() ? tailLeft : tail.size();
        auto chunk = std::span(tail).first(static_cast<std::size_t>(want));

        auto read = file_.readExactAt(offset, chunk);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        for (std::byte byte : chunk) {
            if (byte != std::byte{0}) {
                return fail(ErrorKind::Malformed, "trailing data after cpio trailer", offset);
            }
        }
        offset += chunk.size();
    }

    // NOTE: names_ may have reallocated while indexing, which invalidates the
    // string_view names stored in entries_, so rebind every view to its owner.
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        entries_[index].name = names_[index];
    }
    resolveHardLinks();
    return {};
}

Result<bool> Reader::indexOne(std::uint64_t& offset, std::uint64_t fileSize) {
    auto end = checkedAdd(offset, headerSize);
    if (!end || *end > fileSize) {
        return fail(ErrorKind::Truncated, "cpio archive ends inside a header", offset);
    }

    std::array<std::byte, headerSize> header{};
    auto read = file_.readExactAt(offset, header);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }

    std::string_view magicText(reinterpret_cast<const char*>(header.data()), magicLength);
    if (magicText != newcMagic && magicText != crcMagic) {
        return fail(ErrorKind::Malformed, "unknown cpio magic", offset);
    }

    auto namesize = parseNamesize(header, offset);
    if (!namesize) {
        return tl::unexpected<Error>(namesize.error());
    }
    if (*namesize == 0 || *namesize > limits_.maxNameBytes) {
        return fail(
            *namesize == 0 ? ErrorKind::Malformed : ErrorKind::LimitExceeded,
            *namesize == 0 ? "cpio entry name is missing" : "cpio entry name exceeds limit",
            offset
        );
    }

    auto nameBytes = checkedCast<std::size_t>(*namesize);
    if (!nameBytes) {
        return fail(ErrorKind::LimitExceeded, "cpio entry name exceeds limit", offset);
    }

    auto nameEnd = checkedAdd(*end, *namesize);
    if (!nameEnd || *nameEnd > fileSize) {
        return fail(ErrorKind::Truncated, "cpio archive ends inside a name", offset);
    }

    names_.push_back({});
    auto& stored = names_.back();
    stored.resize(*nameBytes);

    auto nameRead = file_.readExactAt(*end, std::as_writable_bytes(std::span(stored)));
    if (!nameRead) {
        names_.pop_back();
        return tl::unexpected<Error>(nameRead.error());
    }
    if (stored.back() != '\0') {
        names_.pop_back();
        return fail(ErrorKind::Malformed, "cpio entry name is not terminated", offset);
    }
    stored.pop_back();
    if (stored.find('\0') != std::string::npos) {
        names_.pop_back();
        return fail(ErrorKind::Malformed, "cpio entry name contains NUL", offset);
    }

    auto pad = namePadding(*namesize);
    auto dataOffset = checkedAdd(*nameEnd, pad);
    if (!dataOffset || *dataOffset > fileSize) {
        names_.pop_back();
        return fail(ErrorKind::Truncated, "cpio archive ends inside entry padding", offset);
    }

    auto parsed = parseHeader(header, stored, offset, *dataOffset);
    if (!parsed) {
        names_.pop_back();
        return tl::unexpected<Error>(parsed.error());
    }

    if (parsed->trailer) {
        names_.pop_back();
        if (parsed->size != 0) {
            return fail(ErrorKind::Malformed, "cpio trailer carries data", offset);
        }
        offset = *dataOffset;
        return true;
    }

    if (parsed->name.empty()) {
        names_.pop_back();
        return fail(ErrorKind::Malformed, "cpio entry name is empty", offset);
    }
    if (parsed->name.size() > limits_.maxNameBytes) {
        names_.pop_back();
        return fail(ErrorKind::LimitExceeded, "cpio entry name exceeds limit", offset);
    }
    if (parsed->size > limits_.maxEntryBytes) {
        names_.pop_back();
        return fail(ErrorKind::LimitExceeded, "cpio entry exceeds size limit", offset);
    }

    auto total = checkedAdd(totalBytes_, parsed->size);
    if (!total || *total > limits_.maxTotalBytes) {
        names_.pop_back();
        return fail(ErrorKind::LimitExceeded, "cpio total size exceeds limit", offset);
    }
    totalBytes_ = *total;

    auto dataEnd = checkedAdd(*dataOffset, parsed->size);
    if (!dataEnd) {
        names_.pop_back();
        return fail(ErrorKind::Malformed, "cpio entry size overflows", offset);
    }

    auto next = checkedAdd(*dataEnd, dataPadding(parsed->size));
    if (!next || *next > fileSize) {
        names_.pop_back();
        return fail(ErrorKind::Truncated, "cpio entry data extends past end of file", offset);
    }

    if (parsed->kind == EntryKind::Directory && parsed->size != 0) {
        names_.pop_back();
        return fail(ErrorKind::Malformed, "cpio directory carries data", offset);
    }

    entries_.push_back(
        Entry{
            .name = stored,
            .linkTarget = {},
            .dataOffset = *dataOffset,
            .size = parsed->size,
            .mtimeSeconds = parsed->mtimeSeconds,
            .uid = parsed->uid,
            .gid = parsed->gid,
            .mode = parsed->mode,
            .devMajor = parsed->devMajor,
            .devMinor = parsed->devMinor,
            .check = parsed->check,
            .checksum = parsed->checksum,
            .kind = parsed->kind,
        }
    );

    if (parsed->kind == EntryKind::Regular && parsed->nlink > 1) {
        pending_.push_back(
            Pending{
                .index = entries_.size() - 1,
                .identity =
                    Identity{
                        .fsMajor = parsed->fsMajor,
                        .fsMinor = parsed->fsMinor,
                        .ino = parsed->ino,
                    },
                .nlink = parsed->nlink,
            }
        );
    }

    offset = *next;
    return false;
}

void Reader::resolveHardLinks() {
    std::unordered_map<Identity, std::size_t, IdentityHash> carriers;
    carriers.reserve(pending_.size() * 2 + 1);
    for (const auto& link : pending_) {
        if (entries_[link.index].size == 0) {
            continue;
        }
        carriers.try_emplace(link.identity, link.index);
    }

    for (const auto& link : pending_) {
        auto carrier = carriers.find(link.identity);
        if (carrier == carriers.end() || carrier->second == link.index) {
            continue;
        }

        auto& entry = entries_[link.index];
        if (entry.size == 0) {
            entry.kind = EntryKind::HardLink;
            entry.linkTarget = entries_[carrier->second].name;
        }
    }
    pending_.clear();
}

}
