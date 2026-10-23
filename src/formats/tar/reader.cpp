#include "formats/tar/reader.hpp"

#include <span>
#include <utility>

namespace bale::tar {

namespace {

std::uint64_t pick(
    bool local,
    std::uint64_t localValue,
    bool global,
    std::uint64_t globalValue,
    std::uint64_t fallback
) {
    if (local) {
        return localValue;
    }
    return global ? globalValue : fallback;
}

std::string_view pickText(
    bool local,
    const std::string& localValue,
    bool global,
    const std::string& globalValue,
    std::string_view fallback
) {
    if (local) {
        return localValue;
    }
    return global ? std::string_view(globalValue) : fallback;
}

}

Result<const Entry*> Reader::next() {
    if (failure_) {
        return tl::unexpected<Error>(*failure_);
    }
    if (done_) {
        return nullptr;
    }

    auto entry = readNext();
    if (!entry) {
        failure_ = entry.error();
    }
    return entry;
}

Result<const Entry*> Reader::readNext() {
    auto skipped = source_.skip(dataLeft_ + paddingLeft_);
    if (!skipped) {
        return tl::unexpected<Error>(skipped.error());
    }
    dataLeft_ = 0;
    paddingLeft_ = 0;

    localPax_.clear();
    hasLongPath_ = false;
    hasLongLink_ = false;

    while (true) {
        bool pendingMeta = hasLongPath_ || hasLongLink_ || !localPax_.empty();

        auto state = readBlock();
        if (!state) {
            return tl::unexpected<Error>(state.error());
        }
        if (*state != BlockState::Header) {
            return endOfArchive(*state, pendingMeta);
        }

        auto header = parseHeader(block_, position_);
        if (!header) {
            return tl::unexpected<Error>(header.error());
        }

        switch (header->typeflag) {
        case 'x':
        case 'X': {
            auto dataOffset = position_ + blockSize;
            auto read = readMetaData(*header, metaBuffer_);
            if (!read) {
                return tl::unexpected<Error>(read.error());
            }

            auto parsed = parsePaxRecords(metaBuffer_, dataOffset, limits_, localPax_);
            if (!parsed) {
                return tl::unexpected<Error>(parsed.error());
            }
            continue;
        }
        case 'g': {
            auto dataOffset = position_ + blockSize;
            auto read = readMetaData(*header, metaBuffer_);
            if (!read) {
                return tl::unexpected<Error>(read.error());
            }

            auto parsed = parsePaxRecords(metaBuffer_, dataOffset, limits_, globalPax_);
            if (!parsed) {
                return tl::unexpected<Error>(parsed.error());
            }
            continue;
        }
        case 'L':
        case 'K': {
            auto headerOffset = position_;
            auto& target = header->typeflag == 'L' ? longPath_ : longLink_;
            auto read = readMetaData(*header, target);
            if (!read) {
                return tl::unexpected<Error>(read.error());
            }

            auto terminator = target.find('\0');
            if (terminator != std::string::npos) {
                target.resize(terminator);
            }
            if (target.size() > limits_.maxPathBytes) {
                return fail(ErrorKind::LimitExceeded, "tar long name exceeds limit", headerOffset);
            }

            if (header->typeflag == 'L') {
                hasLongPath_ = true;
            } else {
                hasLongLink_ = true;
            }
            continue;
        }
        case 'S':
            return fail(
                ErrorKind::Unsupported,
                "GNU sparse tar entries are not supported",
                position_
            );
        default:
            return finishEntry(*header);
        }
    }
}

Result<void> Reader::readData(std::span<std::byte> out) {
    auto read = readExact(out);
    if (!read) {
        failure_ = read.error();
        return read;
    }

    dataLeft_ -= out.size();
    return {};
}

Result<void> Reader::readExact(std::span<std::byte> out) {
    auto count = source_.readFull(out);
    if (!count) {
        return tl::unexpected<Error>(count.error());
    }
    if (*count < out.size()) {
        return fail(ErrorKind::Truncated, "tar archive ends inside entry data", source_.position());
    }
    return {};
}

Result<Reader::BlockState> Reader::readBlock() {
    position_ = source_.position();
    auto count = source_.readFull(block_);
    if (!count) {
        return tl::unexpected<Error>(count.error());
    }
    if (*count == 0) {
        return BlockState::End;
    }
    if (*count < blockSize) {
        return fail(ErrorKind::Truncated, "tar archive ends inside a header block", position_);
    }
    return isZeroBlock(block_) ? BlockState::Zero : BlockState::Header;
}

Result<std::uint64_t> Reader::padding(std::uint64_t dataOffset, std::uint64_t size) const {
    auto padded = paddedSize(size);
    if (!padded) {
        return fail(ErrorKind::Malformed, "tar entry size overflows", dataOffset);
    }

    auto remaining = source_.remaining();
    if (remaining && *padded > *remaining) {
        return fail(ErrorKind::Truncated, "tar entry data extends past end of file", dataOffset);
    }
    return *padded - size;
}

Result<void> Reader::readMetaData(const Header& header, std::string& buffer) {
    if (header.size > limits_.maxExtendedHeaderBytes) {
        return fail(ErrorKind::LimitExceeded, "tar extended header exceeds limit", position_);
    }

    auto pad = padding(position_ + blockSize, header.size);
    if (!pad) {
        return tl::unexpected<Error>(pad.error());
    }

    buffer.resize(static_cast<std::size_t>(header.size));
    auto read = readExact(std::as_writable_bytes(std::span(buffer)));
    if (!read) {
        return read;
    }
    return source_.skip(*pad);
}

Result<const Entry*> Reader::endOfArchive(BlockState state, bool pendingMeta) {
    if (pendingMeta) {
        return fail(ErrorKind::Malformed, "tar extended header without entry", position_);
    }

    if (state == BlockState::Zero) {
        auto second = readBlock();
        if (!second) {
            return tl::unexpected<Error>(second.error());
        }
        if (*second == BlockState::Header) {
            return fail(ErrorKind::Malformed, "lone zero block before tar header", position_);
        }
    }

    auto finished = source_.finish();
    if (!finished) {
        return tl::unexpected<Error>(finished.error());
    }

    done_ = true;
    return nullptr;
}

Result<const Entry*> Reader::finishEntry(const Header& header) {
    if (entryCount_ >= limits_.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "tar entry count exceeds limit", position_);
    }

    std::string_view path = header.name;
    if (localPax_.hasPath) {
        path = localPax_.path;
    } else if (hasLongPath_) {
        path = longPath_;
    } else if (globalPax_.hasPath) {
        path = globalPax_.path;
    } else if (!header.prefix.empty()) {
        path_.assign(header.prefix);
        path_ += '/';
        path_ += header.name;
        path = path_;
    }

    std::string_view linkTarget = header.linkName;
    if (localPax_.hasLinkPath) {
        linkTarget = localPax_.linkPath;
    } else if (hasLongLink_) {
        linkTarget = longLink_;
    } else if (globalPax_.hasLinkPath) {
        linkTarget = globalPax_.linkPath;
    }

    if (path.size() > limits_.maxPathBytes || linkTarget.size() > limits_.maxPathBytes) {
        return fail(ErrorKind::LimitExceeded, "tar path exceeds limit", position_);
    }

    auto kind = entryKind(header.typeflag);
    auto size =
        pick(localPax_.hasSize, localPax_.size, globalPax_.hasSize, globalPax_.size, header.size);
    if (!entryHasData(kind)) {
        size = 0;
    }

    auto dataOffset = position_ + blockSize;
    auto pad = padding(dataOffset, size);
    if (!pad) {
        return tl::unexpected<Error>(pad.error());
    }

    entry_ = Entry{};
    entry_.path = path;
    entry_.linkTarget = linkTarget;
    entry_.uname = pickText(
        localPax_.hasUname,
        localPax_.uname,
        globalPax_.hasUname,
        globalPax_.uname,
        header.uname
    );
    entry_.gname = pickText(
        localPax_.hasGname,
        localPax_.gname,
        globalPax_.hasGname,
        globalPax_.gname,
        header.gname
    );
    entry_.headerOffset = position_;
    entry_.dataOffset = dataOffset;
    entry_.size = size;
    entry_.uid =
        pick(localPax_.hasUid, localPax_.uid, globalPax_.hasUid, globalPax_.uid, header.uid);
    entry_.gid =
        pick(localPax_.hasGid, localPax_.gid, globalPax_.hasGid, globalPax_.gid, header.gid);
    entry_.mtimeSeconds = header.mtime;
    entry_.mode = header.mode;
    entry_.devMajor = header.devMajor;
    entry_.devMinor = header.devMinor;
    entry_.kind = kind;
    entry_.format = header.format;
    entry_.typeflag = header.typeflag;

    if (localPax_.hasMtime) {
        entry_.mtimeSeconds = localPax_.mtimeSeconds;
        entry_.mtimeNanoseconds = localPax_.mtimeNanoseconds;
    } else if (globalPax_.hasMtime) {
        entry_.mtimeSeconds = globalPax_.mtimeSeconds;
        entry_.mtimeNanoseconds = globalPax_.mtimeNanoseconds;
    }

    ++entryCount_;
    dataLeft_ = size;
    paddingLeft_ = *pad;
    return &entry_;
}

}
