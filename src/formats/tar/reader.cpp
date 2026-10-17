#include "formats/tar/reader.hpp"

#include "base/checked.hpp"

#include <span>

namespace bale {

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

Result<TarReader> TarReader::open(const File& file, const TarLimits& limits) {
    auto size = file.size();
    if (!size) {
        return std::unexpected(size.error());
    }
    return TarReader(file, *size, limits);
}

Result<const TarEntry*> TarReader::next() {
    if (failure_) {
        return std::unexpected(*failure_);
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

Result<const TarEntry*> TarReader::readNext() {
    localPax_.clear();
    hasLongPath_ = false;
    hasLongLink_ = false;

    while (true) {
        bool pendingMeta = hasLongPath_ || hasLongLink_ || !localPax_.empty();

        auto state = readBlock(position_);
        if (!state) {
            return std::unexpected(state.error());
        }
        if (*state != BlockState::Header) {
            return endOfArchive(*state, pendingMeta);
        }

        auto header = parseTarHeader(block_, position_);
        if (!header) {
            return std::unexpected(header.error());
        }

        switch (header->typeflag) {
        case 'x':
        case 'X': {
            auto dataOffset = position_ + tarBlockSize;
            auto read = readMetaData(*header, metaBuffer_);
            if (!read) {
                return std::unexpected(read.error());
            }

            auto parsed = parsePaxRecords(metaBuffer_, dataOffset, limits_, localPax_);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            continue;
        }
        case 'g': {
            auto dataOffset = position_ + tarBlockSize;
            auto read = readMetaData(*header, metaBuffer_);
            if (!read) {
                return std::unexpected(read.error());
            }

            auto parsed = parsePaxRecords(metaBuffer_, dataOffset, limits_, globalPax_);
            if (!parsed) {
                return std::unexpected(parsed.error());
            }
            continue;
        }
        case 'L':
        case 'K': {
            auto headerOffset = position_;
            auto& target = header->typeflag == 'L' ? longPath_ : longLink_;
            auto read = readMetaData(*header, target);
            if (!read) {
                return std::unexpected(read.error());
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

Result<TarReader::BlockState> TarReader::readBlock(std::uint64_t offset) {
    auto remaining = fileSize_ - offset;
    if (remaining == 0) {
        return BlockState::End;
    }
    if (remaining < tarBlockSize) {
        return fail(ErrorKind::Truncated, "tar archive ends inside a header block", offset);
    }

    auto read = file_->readExactAt(offset, block_);
    if (!read) {
        return std::unexpected(read.error());
    }
    return isZeroTarBlock(block_) ? BlockState::Zero : BlockState::Header;
}

Result<std::uint64_t> TarReader::dataEnd(std::uint64_t dataOffset, std::uint64_t size) const {
    auto padded = tarPaddedSize(size);
    if (!padded) {
        return fail(ErrorKind::Malformed, "tar entry size overflows", dataOffset);
    }
    if (!fitsWithin(dataOffset, *padded, fileSize_)) {
        return fail(ErrorKind::Truncated, "tar entry data extends past end of file", dataOffset);
    }
    return dataOffset + *padded;
}

Result<void> TarReader::readMetaData(const TarHeader& header, std::string& buffer) {
    if (header.size > limits_.maxExtendedHeaderBytes) {
        return fail(ErrorKind::LimitExceeded, "tar extended header exceeds limit", position_);
    }

    auto dataOffset = position_ + tarBlockSize;
    auto end = dataEnd(dataOffset, header.size);
    if (!end) {
        return std::unexpected(end.error());
    }

    buffer.resize(static_cast<std::size_t>(header.size));
    auto read = file_->readExactAt(dataOffset, std::as_writable_bytes(std::span(buffer)));
    if (!read) {
        return read;
    }

    position_ = *end;
    return {};
}

Result<const TarEntry*> TarReader::endOfArchive(BlockState state, bool pendingMeta) {
    if (pendingMeta) {
        return fail(ErrorKind::Malformed, "tar extended header without entry", position_);
    }

    if (state == BlockState::Zero) {
        auto second = readBlock(position_ + tarBlockSize);
        if (!second) {
            return std::unexpected(second.error());
        }
        if (*second == BlockState::Header) {
            return fail(
                ErrorKind::Malformed,
                "lone zero block before tar header",
                position_ + tarBlockSize
            );
        }
    }

    done_ = true;
    return nullptr;
}

Result<const TarEntry*> TarReader::finishEntry(const TarHeader& header) {
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

    auto kind = tarEntryKind(header.typeflag);
    auto size =
        pick(localPax_.hasSize, localPax_.size, globalPax_.hasSize, globalPax_.size, header.size);
    if (!tarEntryHasData(kind)) {
        size = 0;
    }

    auto dataOffset = position_ + tarBlockSize;
    auto end = dataEnd(dataOffset, size);
    if (!end) {
        return std::unexpected(end.error());
    }

    entry_ = TarEntry{};
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
    position_ = *end;
    return &entry_;
}

}
