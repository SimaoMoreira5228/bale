#include "formats/sevenzip/writer.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "formats/sevenzip/coding.hpp"
#include "formats/sevenzip/encode.hpp"
#include "formats/sevenzip/methods.hpp"

#include <algorithm>
#include <array>
#include <span>

namespace bale::sevenzip {

namespace {

constexpr std::uint32_t permissionMask = 0777;
constexpr std::uint32_t typeRegular = 0100000;
constexpr std::uint32_t typeDirectory = 0040000;
constexpr std::uint32_t typeSymlink = 0120000;
constexpr std::uint32_t winFile = 0x20;
constexpr std::uint32_t winDirectory = 0x10;
constexpr std::uint32_t defaultFilePermission = 0644;
constexpr std::uint32_t defaultDirectoryPermission = 0755;
constexpr std::int64_t fileTimeOffset = 116'444'736'000'000'000LL;

void put8(std::vector<std::byte>& out, std::uint8_t value) {
    out.push_back(static_cast<std::byte>(value));
}

void put16le(std::vector<std::byte>& out, std::uint16_t value) {
    std::array<std::byte, 2> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

void put32le(std::vector<std::byte>& out, std::uint32_t value) {
    std::array<std::byte, 4> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

void put64le(std::vector<std::byte>& out, std::uint64_t value) {
    std::array<std::byte, 8> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

void putNumber(std::vector<std::byte>& out, std::uint64_t value) {
    if (value < 0x80) {
        put8(out, static_cast<std::uint8_t>(value));
        return;
    }

    std::uint8_t extra = 0;
    while (value >= (std::uint64_t{1} << (7 + 7 * extra))) {
        ++extra;
    }

    std::uint8_t first = 0;
    for (std::uint8_t index = 0; index < extra; ++index) {
        first |= static_cast<std::uint8_t>(0x80 >> index);
    }
    first |= static_cast<std::uint8_t>(value >> (8 * extra));
    put8(out, first);
    for (std::uint8_t index = 0; index < extra; ++index) {
        put8(out, static_cast<std::uint8_t>(value >> (8 * index)));
    }
}

void setBit(std::vector<std::byte>& bits, std::uint64_t index) {
    bits[index / 8] |= static_cast<std::byte>(0x80 >> (index % 8));
}

std::span<const std::uint8_t> idFor(Codec codec) {
    switch (codec) {
    case Codec::Copy:
        return methodCopy;
    case Codec::Lzma1:
        return methodLzma1;
    case Codec::Lzma2:
        return methodLzma2;
    case Codec::Deflate:
        return methodDeflate;
    case Codec::Bzip2:
        return methodBzip2;
    }
    return methodCopy;
}

std::optional<std::uint64_t> toFileTime(std::int64_t nanoseconds) {
    std::int64_t units = nanoseconds / 100;
    if (nanoseconds % 100 < 0) {
        --units;
    }
    std::int64_t stamp = fileTimeOffset + units;
    if (stamp < 0) {
        return std::nullopt;
    }
    return static_cast<std::uint64_t>(stamp);
}

Result<void> appendUtf16(std::vector<std::byte>& out, std::string_view text) {
    std::size_t index = 0;
    while (index < text.size()) {
        auto lead = static_cast<unsigned char>(text[index]);
        char32_t point = 0;
        std::size_t width = 0;
        if (lead < 0x80) {
            point = lead;
            width = 1;
        } else if ((lead & 0xE0) == 0xC0) {
            point = lead & 0x1F;
            width = 2;
        } else if ((lead & 0xF0) == 0xE0) {
            point = lead & 0x0F;
            width = 3;
        } else if ((lead & 0xF8) == 0xF0) {
            point = lead & 0x07;
            width = 4;
        } else {
            return fail(ErrorKind::Malformed, "7z entry name is not valid UTF-8");
        }
        if (text.size() - index < width) {
            return fail(ErrorKind::Malformed, "7z entry name is not valid UTF-8");
        }
        for (std::size_t tail = 1; tail < width; ++tail) {
            auto unit = static_cast<unsigned char>(text[index + tail]);
            if ((unit & 0xC0) != 0x80) {
                return fail(ErrorKind::Malformed, "7z entry name is not valid UTF-8");
            }
            point = (point << 6) | (unit & 0x3F);
        }
        if ((width == 2 && point < 0x80) || (width == 3 && point < 0x800) ||
            (width == 4 && point < 0x10000)) {
            return fail(ErrorKind::Malformed, "7z entry name is not valid UTF-8");
        }
        if (point > 0x10FFFF || (point >= 0xD800 && point <= 0xDFFF)) {
            return fail(ErrorKind::Malformed, "7z entry name is not valid UTF-8");
        }

        if (point < 0x10000) {
            put16le(out, static_cast<std::uint16_t>(point));
        } else {
            point -= 0x10000;
            put16le(out, static_cast<std::uint16_t>(0xD800 + (point >> 10)));
            put16le(out, static_cast<std::uint16_t>(0xDC00 + (point & 0x3FF)));
        }
        index += width;
    }
    put16le(out, 0);
    return {};
}

}

Result<Writer> Writer::create(File file, const WriterOptions& options) {
    switch (options.codec) {
    case Codec::Copy:
        break;
    case Codec::Deflate:
    case Codec::Lzma1:
    case Codec::Lzma2:
        if (options.level < 0 || options.level > 9) {
            return fail(ErrorKind::Unsupported, "7z compression level out of range");
        }
        break;
    case Codec::Bzip2:
        if (options.level < 1 || options.level > 9) {
            return fail(ErrorKind::Unsupported, "7z bzip2 compression level out of range");
        }
        break;
    }

    std::vector<std::byte> placeholder(signatureSize, std::byte{0});
    auto written = file.append(placeholder);
    if (!written) {
        return std::unexpected(written.error());
    }
    return Writer(std::move(file), options);
}

Result<void> Writer::check() const {
    if (failure_) {
        return std::unexpected(*failure_);
    }
    if (finished_) {
        return fail(ErrorKind::Malformed, "7z writer already finished");
    }
    return {};
}

Result<void> Writer::poison(const Error& error) {
    if (!failure_) {
        failure_ = error;
    }
    return std::unexpected(*failure_);
}

Result<void> Writer::put(std::span<const std::byte> data) {
    auto end = checkedAdd(position_, data.size());
    if (!end) {
        return poison(Error{.kind = ErrorKind::LimitExceeded, .what = "7z archive too large"});
    }
    auto written = file_.append(data);
    if (!written) {
        return poison(written.error());
    }
    position_ = *end;
    return {};
}

Result<void> Writer::closeEntry() {
    if (dataLeft_ != 0) {
        return poison(
            Error{.kind = ErrorKind::Malformed, .what = "7z entry data shorter than its size"}
        );
    }
    if (!streamOpen_) {
        return {};
    }
    streamOpen_ = false;

    FolderBuild& folder = folders_[streamFolder_];
    EntryMeta& meta = metas_.back();
    folder.subSizes.push_back(meta.size);
    folder.subCrcs.push_back(entryCrc_.value());
    meta.crc = entryCrc_.value();

    if (!options_.solid) {
        auto finished = finishFolder(folder);
        if (!finished) {
            return finished;
        }
    }
    return {};
}

Result<void> Writer::finishFolder(FolderBuild& folder) {
    if (!streamEncoder_) {
        return fail(ErrorKind::Malformed, "7z folder encoder is missing");
    }
    auto index = static_cast<std::uint64_t>(&folder - folders_.data());
    PackedSink sink = [this, index](std::span<const std::byte> chunk) -> Result<void> {
        FolderBuild& target = folders_[static_cast<std::size_t>(index)];
        auto end = checkedAdd(target.packSize, chunk.size());
        if (!end) {
            return fail(ErrorKind::LimitExceeded, "7z pack stream too large");
        }
        target.packSize = *end;
        target.packCrc.update(chunk);
        return put(chunk);
    };
    auto flushed = streamEncoder_->supply({}, true, sink);
    if (!flushed) {
        return poison(flushed.error());
    }
    streamEncoder_.reset();
    return {};
}

Result<void> Writer::startStreamFile(const WriteEntry& entry, std::string name) {
    std::uint64_t folderIndex = 0;
    if (options_.solid && !folders_.empty()) {
        folderIndex = 0;
    } else {
        if (folders_.size() >= options_.limits.maxFolders) {
            return fail(ErrorKind::LimitExceeded, "7z folder count exceeds limit");
        }
        folderIndex = folders_.size();
        folders_.push_back(FolderBuild{});
    }

    FolderBuild& folder = folders_[static_cast<std::size_t>(folderIndex)];
    if (!streamEncoder_) {
        std::vector<std::byte> props;
        auto encoder = FolderEncoder::create(options_.codec, options_.level, props);
        if (!encoder) {
            return poison(encoder.error());
        }
        folder.props = std::move(props);
        streamEncoder_.emplace(std::move(*encoder));
        streamFolder_ = folderIndex;
    }

    auto end = checkedAdd(folder.unpackSize, entry.size);
    if (!end || *end > options_.limits.maxFolderBytes) {
        return fail(ErrorKind::LimitExceeded, "7z folder exceeds size limit");
    }
    folder.unpackSize = *end;

    EntryMeta meta;
    meta.name = std::move(name);
    meta.hasStream = true;
    meta.folder = folderIndex;
    meta.size = entry.size;
    meta.fileTime = entry.mtimeNanoseconds.and_then(toFileTime);
    std::uint32_t mode =
        typeRegular | (entry.mode.value_or(defaultFilePermission) & permissionMask);
    meta.attributes = (mode << 16) | winFile;
    auto encoded = appendUtf16(meta.nameUtf16, meta.name);
    if (!encoded) {
        return encoded;
    }

    dataLeft_ = entry.size;
    entryCrc_ = Crc32{};
    metas_.push_back(std::move(meta));
    streamOpen_ = true;
    return {};
}

Result<void> Writer::add(const WriteEntry& entry) {
    auto usable = check();
    if (!usable) {
        return usable;
    }
    auto closed = closeEntry();
    if (!closed) {
        return closed;
    }

    if (entry.path.empty() || entry.path.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "7z entry path empty or containing NUL");
    }
    if (metas_.size() >= options_.limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "7z entry count exceeds limit");
    }
    if (entry.path.size() > options_.limits.maxNameBytes) {
        return fail(ErrorKind::LimitExceeded, "7z entry name exceeds limit");
    }

    std::string name(entry.path);

    if (entry.kind != WriteKind::File && entry.size != 0) {
        return fail(ErrorKind::Malformed, "only regular 7z entries carry data");
    }

    if (entry.kind == WriteKind::Directory) {
        while (name.ends_with('/')) {
            name.pop_back();
        }
        if (name.empty()) {
            return fail(ErrorKind::UnsafePath, "7z entry path empty or containing NUL");
        }
    } else if (name.ends_with('/')) {
        return fail(ErrorKind::Malformed, "only 7z directories end in a slash");
    }
    if (!seen_.insert(name).second) {
        return fail(ErrorKind::AlreadyExists, "7z duplicate entry name");
    }

    if (entry.kind == WriteKind::Directory) {
        EntryMeta meta;
        meta.name = name;
        meta.hasStream = false;
        meta.directory = true;
        meta.fileTime = entry.mtimeNanoseconds.and_then(toFileTime);
        std::uint32_t mode =
            typeDirectory | (entry.mode.value_or(defaultDirectoryPermission) & permissionMask);
        meta.attributes = (mode << 16) | winDirectory;
        auto encoded = appendUtf16(meta.nameUtf16, meta.name);
        if (!encoded) {
            seen_.erase(name);
            return encoded;
        }
        metas_.push_back(std::move(meta));
        return {};
    }

    if (entry.kind == WriteKind::Symlink) {
        if (entry.linkTarget.empty()) {
            seen_.erase(name);
            return fail(ErrorKind::Malformed, "7z symlink without a target");
        }
        auto target = std::as_bytes(std::span(entry.linkTarget.data(), entry.linkTarget.size()));
        if (target.size() > options_.limits.maxEntryBytes) {
            seen_.erase(name);
            return fail(ErrorKind::LimitExceeded, "7z entry exceeds size limit");
        }
        auto started = startStreamFile(
            WriteEntry{.size = target.size(), .mtimeNanoseconds = entry.mtimeNanoseconds},
            name
        );
        if (!started) {
            seen_.erase(name);
            return started;
        }
        metas_.back().attributes = ((typeSymlink | permissionMask) << 16) | winFile;
        auto written = write(target);
        if (!written) {
            return written;
        }
        return closeEntry();
    }

    if (entry.size > options_.limits.maxEntryBytes) {
        seen_.erase(name);
        return fail(ErrorKind::LimitExceeded, "7z entry exceeds size limit");
    }
    if (entry.size == 0) {
        EntryMeta meta;
        meta.name = name;
        meta.hasStream = false;
        meta.emptyFile = true;
        meta.fileTime = entry.mtimeNanoseconds.and_then(toFileTime);
        std::uint32_t mode =
            typeRegular | (entry.mode.value_or(defaultFilePermission) & permissionMask);
        meta.attributes = (mode << 16) | winFile;
        auto encoded = appendUtf16(meta.nameUtf16, meta.name);
        if (!encoded) {
            seen_.erase(name);
            return encoded;
        }
        metas_.push_back(std::move(meta));
        return {};
    }
    auto started = startStreamFile(entry, name);
    if (!started) {
        seen_.erase(name);
        return started;
    }
    return {};
}

Result<void> Writer::write(std::span<const std::byte> data) {
    auto usable = check();
    if (!usable) {
        return usable;
    }
    if (!streamOpen_ || !streamEncoder_ || data.size() > dataLeft_) {
        return poison(
            Error{.kind = ErrorKind::Malformed, .what = "7z entry data longer than its size"}
        );
    }
    dataLeft_ -= data.size();
    if (data.empty()) {
        return {};
    }

    entryCrc_.update(data);
    PackedSink sink = [this](std::span<const std::byte> chunk) -> Result<void> {
        FolderBuild& folder = folders_[streamFolder_];
        auto end = checkedAdd(folder.packSize, chunk.size());
        if (!end) {
            return fail(ErrorKind::LimitExceeded, "7z pack stream too large");
        }
        folder.packSize = *end;
        folder.packCrc.update(chunk);
        return put(chunk);
    };
    auto supplied = streamEncoder_->supply(data, false, sink);
    if (!supplied) {
        return poison(supplied.error());
    }
    return {};
}

Result<std::vector<std::byte>> Writer::buildHeader() const {
    std::vector<std::byte> header;
    header.push_back(std::byte{nidHeader});
    header.push_back(std::byte{nidMainStreams});

    if (!folders_.empty()) {
        header.push_back(std::byte{nidPackInfo});
        putNumber(header, 0);
        putNumber(header, folders_.size());
        header.push_back(std::byte{nidSize});
        for (const auto& folder : folders_) {
            putNumber(header, folder.packSize);
        }
        header.push_back(std::byte{nidCrc});
        put8(header, 1);
        for (const auto& folder : folders_) {
            put32le(header, folder.packCrc.value());
        }
        header.push_back(std::byte{nidEnd});

        header.push_back(std::byte{nidUnpackInfo});
        header.push_back(std::byte{nidFolder});
        putNumber(header, folders_.size());
        put8(header, 0);
        for (const auto& folder : folders_) {
            putNumber(header, 1);
            auto id = idFor(options_.codec);
            std::uint8_t flags = static_cast<std::uint8_t>(id.size());
            if (!folder.props.empty()) {
                flags |= 0x20;
            }
            put8(header, flags);
            for (std::uint8_t idByte : id) {
                put8(header, idByte);
            }
            if (!folder.props.empty()) {
                putNumber(header, folder.props.size());
                header.insert(header.end(), folder.props.begin(), folder.props.end());
            }
        }
        header.push_back(std::byte{nidCoderUnpackSize});
        for (const auto& folder : folders_) {
            putNumber(header, folder.unpackSize);
        }
        // NOTE: no folder CRCs are emitted. They only repeat the per-entry
        // CRCs below, 7-Zip itself omits them, and real 7-Zip rejects them
        // in single-substream folders alongside empty entries.
        header.push_back(std::byte{nidEnd});

        bool anyMulti = false;
        std::uint64_t streams = 0;
        for (const auto& folder : folders_) {
            anyMulti = anyMulti || folder.subSizes.size() > 1;
            auto next = checkedAdd(streams, folder.subSizes.size());
            if (!next) {
                return fail(ErrorKind::LimitExceeded, "7z stream count exceeds limit");
            }
            streams = *next;
        }
        header.push_back(std::byte{nidSubStreams});
        if (anyMulti) {
            header.push_back(std::byte{nidNumUnpackStream});
            for (const auto& folder : folders_) {
                putNumber(header, folder.subSizes.size());
            }
            header.push_back(std::byte{nidSize});
            for (const auto& folder : folders_) {
                for (std::size_t index = 0; index + 1 < folder.subSizes.size(); ++index) {
                    putNumber(header, folder.subSizes[index]);
                }
            }
        }
        if (streams != 0) {
            header.push_back(std::byte{nidCrc});
            put8(header, 1);
            for (const auto& folder : folders_) {
                for (auto crc : folder.subCrcs) {
                    put32le(header, crc);
                }
            }
        }
        header.push_back(std::byte{nidEnd});
    }
    header.push_back(std::byte{nidEnd});

    header.push_back(std::byte{nidFilesInfo});
    putNumber(header, metas_.size());

    std::uint64_t emptyCount = 0;
    for (const auto& meta : metas_) {
        if (!meta.hasStream) {
            ++emptyCount;
        }
    }
    if (emptyCount != 0) {
        header.push_back(std::byte{nidEmptyStream});
        std::vector<std::byte> bits((metas_.size() + 7) / 8, std::byte{0});
        for (std::size_t index = 0; index < metas_.size(); ++index) {
            if (!metas_[index].hasStream) {
                setBit(bits, index);
            }
        }
        putNumber(header, bits.size());
        header.insert(header.end(), bits.begin(), bits.end());

        header.push_back(std::byte{nidEmptyFile});
        std::vector<std::byte> fileBits(
            (static_cast<std::size_t>(emptyCount) + 7) / 8,
            std::byte{0}
        );
        std::uint64_t cursor = 0;
        for (const auto& meta : metas_) {
            if (meta.hasStream) {
                continue;
            }
            if (meta.emptyFile) {
                setBit(fileBits, cursor);
            }
            ++cursor;
        }
        putNumber(header, fileBits.size());
        header.insert(header.end(), fileBits.begin(), fileBits.end());
    }

    {
        header.push_back(std::byte{nidName});
        std::vector<std::byte> names{std::byte{0}};
        for (const auto& meta : metas_) {
            names.insert(names.end(), meta.nameUtf16.begin(), meta.nameUtf16.end());
        }
        putNumber(header, names.size());
        header.insert(header.end(), names.begin(), names.end());
    }

    bool anyTime = false;
    for (const auto& meta : metas_) {
        anyTime = anyTime || meta.fileTime.has_value();
    }
    if (anyTime) {
        header.push_back(std::byte{nidMTime});
        std::vector<std::byte> times;
        bool allDefined = true;
        for (const auto& meta : metas_) {
            allDefined = allDefined && meta.fileTime.has_value();
        }
        put8(times, allDefined ? 1 : 0);
        if (!allDefined) {
            std::vector<std::byte> bits((metas_.size() + 7) / 8, std::byte{0});
            for (std::size_t index = 0; index < metas_.size(); ++index) {
                if (metas_[index].fileTime) {
                    setBit(bits, index);
                }
            }
            times.insert(times.end(), bits.begin(), bits.end());
        }
        put8(times, 0);
        for (const auto& meta : metas_) {
            if (meta.fileTime) {
                put64le(times, *meta.fileTime);
            }
        }
        putNumber(header, times.size());
        header.insert(header.end(), times.begin(), times.end());
    }

    {
        header.push_back(std::byte{nidWinAttributes});
        std::vector<std::byte> attributes{std::byte{1}, std::byte{0}};
        for (const auto& meta : metas_) {
            put32le(attributes, meta.attributes);
        }
        putNumber(header, attributes.size());
        header.insert(header.end(), attributes.begin(), attributes.end());
    }

    header.push_back(std::byte{nidEnd});
    header.push_back(std::byte{nidEnd});
    return header;
}

Result<std::uint64_t> Writer::finish(bool durable) {
    auto usable = check();
    if (!usable) {
        return std::unexpected(usable.error());
    }
    auto closed = closeEntry();
    if (!closed) {
        return std::unexpected(closed.error());
    }
    if (streamEncoder_) {
        auto finished = finishFolder(folders_[streamFolder_]);
        if (!finished) {
            return std::unexpected(finished.error());
        }
    }

    auto header = buildHeader();
    if (!header) {
        return std::unexpected(header.error());
    }
    if (header->size() > options_.limits.maxHeaderBytes) {
        return std::unexpected(
            poison(Error{.kind = ErrorKind::LimitExceeded, .what = "7z header exceeds limit"})
                .error()
        );
    }

    auto packSize = position_ - signatureSize;
    auto stored = put(*header);
    if (!stored) {
        return std::unexpected(stored.error());
    }

    std::array<std::byte, signatureSize> signature{};
    signature[0] = std::byte{'7'};
    signature[1] = std::byte{'z'};
    signature[2] = std::byte{0xBC};
    signature[3] = std::byte{0xAF};
    signature[4] = std::byte{0x27};
    signature[5] = std::byte{0x1C};
    signature[6] = std::byte{0x00};
    signature[7] = std::byte{0x04};
    storeLe(signature.data() + 12, packSize);
    auto headerSize = checkedCast<std::uint64_t>(header->size());
    if (!headerSize) {
        return std::unexpected(
            poison(Error{.kind = ErrorKind::LimitExceeded, .what = "7z header exceeds limit"})
                .error()
        );
    }
    storeLe(signature.data() + 20, *headerSize);
    storeLe(signature.data() + 28, Crc32::of(*header));
    storeLe(signature.data() + 8, Crc32::of(std::span(signature).subspan(12, 20)));
    auto patched = file_.writeAt(0, signature);
    if (!patched) {
        return std::unexpected(poison(patched.error()).error());
    }

    if (durable) {
        auto synced = file_.sync();
        if (!synced) {
            return std::unexpected(poison(synced.error()).error());
        }
    }
    finished_ = true;
    return position_;
}

}
