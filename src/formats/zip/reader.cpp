#include "formats/zip/reader.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace bale::zip {

namespace {

constexpr std::uint32_t localHeaderSignature = 0x04034b50;
constexpr std::uint32_t centralHeaderSignature = 0x02014b50;
constexpr std::uint32_t endRecordSignature = 0x06054b50;
constexpr std::uint32_t zip64LocatorSignature = 0x07064b50;
constexpr std::uint32_t zip64EndRecordSignature = 0x06064b50;
constexpr std::size_t localHeaderSize = 30;
constexpr std::size_t centralHeaderSize = 46;
constexpr std::size_t zip64LocatorSize = 20;
constexpr std::size_t zip64EndRecordSize = 56;
constexpr std::uint64_t zip64EndRecordMinBody = 44;
constexpr std::uint16_t saturated16 = 0xFFFF;
constexpr std::uint32_t saturated32 = 0xFFFFFFFF;

constexpr std::array<char32_t, 128> cp437High{
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF,
    0x00EE, 0x00EC, 0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
    0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA,
    0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557,
    0x255D, 0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4,
    0x221E, 0x03C6, 0x03B5, 0x2229, 0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
};

struct EndRecord {
    std::uint64_t entryCount = 0;
    std::uint64_t directorySize = 0;
    std::uint64_t directoryOffset = 0;
    std::uint64_t prefix = 0;
    std::uint16_t commentLength = 0;
    bool zip64 = false;
};

struct Zip64End {
    std::uint64_t start = 0;
    std::uint64_t prefix = 0;
    std::uint64_t entryCount = 0;
    std::uint64_t directorySize = 0;
    std::uint64_t directoryOffset = 0;
};

bool hasSignature(std::span<const std::byte> data, std::size_t at, std::uint32_t signature) {
    return data.size() >= 4 && at <= data.size() - 4 &&
        loadLe<std::uint32_t>(data.data() + at) == signature;
}

bool reachesEnd(std::span<const std::byte> tail, std::size_t at) {
    auto commentLength = loadLe<std::uint16_t>(tail.data() + at + 20);
    return tail.size() - at - endRecordSize == commentLength;
}

char32_t cp437CodePoint(unsigned char byte) {
    if (byte < 0x80) {
        return byte;
    }
    return cp437High[byte - 0x80];
}

std::size_t utf8Length(char32_t codePoint) {
    if (codePoint <= 0x7F) {
        return 1;
    }
    if (codePoint <= 0x7FF) {
        return 2;
    }
    return 3;
}

void appendUtf8(char32_t codePoint, std::string& out) {
    if (codePoint <= 0x7F) {
        out.push_back(static_cast<char>(codePoint));
        return;
    }
    if (codePoint <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
        out.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        return;
    }
    out.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
    out.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
}

Result<bool> readSignatureAt(const File& file, std::uint64_t offset, std::uint32_t signature) {
    std::array<std::byte, 4> bytes{};
    auto read = file.readExactAt(offset, bytes);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    return loadLe<std::uint32_t>(bytes.data()) == signature;
}

Result<std::optional<Zip64End>>
readZip64Record(const File& file, std::uint64_t at, std::uint64_t locatorPosition) {
    if (at > locatorPosition || locatorPosition - at < zip64EndRecordSize) {
        return std::optional<Zip64End>{};
    }

    std::array<std::byte, zip64EndRecordSize> record{};
    auto read = file.readExactAt(at, record);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    if (loadLe<std::uint32_t>(record.data()) != zip64EndRecordSignature) {
        return std::optional<Zip64End>{};
    }

    auto bodySize = loadLe<std::uint64_t>(record.data() + 4);
    if (bodySize < zip64EndRecordMinBody || bodySize != locatorPosition - at - 12) {
        return fail(ErrorKind::Malformed, "ZIP64 end record size inconsistent", at);
    }

    auto disk = loadLe<std::uint32_t>(record.data() + 16);
    auto directoryDisk = loadLe<std::uint32_t>(record.data() + 20);
    auto entriesOnDisk = loadLe<std::uint64_t>(record.data() + 24);

    Zip64End end;
    end.start = at;
    end.entryCount = loadLe<std::uint64_t>(record.data() + 32);
    end.directorySize = loadLe<std::uint64_t>(record.data() + 40);
    end.directoryOffset = loadLe<std::uint64_t>(record.data() + 48);

    if (disk != 0 || directoryDisk != 0 || entriesOnDisk != end.entryCount) {
        return fail(ErrorKind::Unsupported, "multi-disk ZIP64 archives are not supported", at);
    }
    return std::optional<Zip64End>{end};
}

Result<Zip64End> readZip64End(const File& file, std::uint64_t locatorPosition) {
    std::array<std::byte, zip64LocatorSize> locator{};
    auto read = file.readExactAt(locatorPosition, locator);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }

    auto disk = loadLe<std::uint32_t>(locator.data() + 4);
    auto recordOffset = loadLe<std::uint64_t>(locator.data() + 8);
    auto totalDisks = loadLe<std::uint32_t>(locator.data() + 16);
    if (disk != 0 || totalDisks > 1) {
        return fail(
            ErrorKind::Unsupported,
            "multi-disk ZIP64 archives are not supported",
            locatorPosition
        );
    }

    auto direct = readZip64Record(file, recordOffset, locatorPosition);
    if (!direct) {
        return tl::unexpected<Error>(direct.error());
    }
    if (*direct) {
        return **direct;
    }

    if (locatorPosition < zip64EndRecordSize) {
        return fail(ErrorKind::Malformed, "ZIP64 end record not found", locatorPosition);
    }

    auto shifted = locatorPosition - zip64EndRecordSize;
    if (shifted <= recordOffset) {
        return fail(ErrorKind::Malformed, "ZIP64 end record not found", locatorPosition);
    }

    auto moved = readZip64Record(file, shifted, locatorPosition);
    if (!moved) {
        return tl::unexpected<Error>(moved.error());
    }
    if (!*moved) {
        return fail(ErrorKind::Malformed, "ZIP64 end record not found", locatorPosition);
    }

    auto end = **moved;
    end.prefix = shifted - recordOffset;
    return end;
}

bool agrees(std::uint64_t classic, std::uint64_t saturated, std::uint64_t zip64) {
    return classic == saturated || classic == zip64;
}

Result<EndRecord> readEndRecord(
    const File& file,
    std::span<const std::byte> tail,
    std::size_t at,
    std::uint64_t tailOffset,
    const Limits& limits
) {
    const std::byte* fields = tail.data() + at;
    auto position = tailOffset + at;
    auto disk = loadLe<std::uint16_t>(fields + 4);
    auto directoryDisk = loadLe<std::uint16_t>(fields + 6);
    auto entriesOnDisk = loadLe<std::uint16_t>(fields + 8);
    auto entryCount = loadLe<std::uint16_t>(fields + 10);
    auto directorySize = loadLe<std::uint32_t>(fields + 12);
    auto directoryOffset = loadLe<std::uint32_t>(fields + 16);

    EndRecord end;
    end.commentLength = loadLe<std::uint16_t>(fields + 20);
    end.entryCount = entryCount;
    end.directorySize = directorySize;
    end.directoryOffset = directoryOffset;

    bool saturated = disk == saturated16 || directoryDisk == saturated16 ||
        entriesOnDisk == saturated16 || entryCount == saturated16 || directorySize == saturated32 ||
        directoryOffset == saturated32;

    bool locatorPresent = false;
    if (position >= zip64LocatorSize) {
        auto signature = readSignatureAt(file, position - zip64LocatorSize, zip64LocatorSignature);
        if (!signature) {
            return tl::unexpected<Error>(signature.error());
        }
        locatorPresent = *signature;
    }

    std::uint64_t directoryEnd = position;
    std::optional<std::uint64_t> recordPrefix;
    if (locatorPresent) {
        auto zip64 = readZip64End(file, position - zip64LocatorSize);
        if (!zip64) {
            return tl::unexpected<Error>(zip64.error());
        }

        bool consistent = agrees(disk, saturated16, 0) && agrees(directoryDisk, saturated16, 0) &&
            agrees(entriesOnDisk, saturated16, zip64->entryCount) &&
            agrees(entryCount, saturated16, zip64->entryCount) &&
            agrees(directorySize, saturated32, zip64->directorySize) &&
            agrees(directoryOffset, saturated32, zip64->directoryOffset);
        if (!consistent) {
            return fail(
                ErrorKind::Malformed,
                "end record disagrees with ZIP64 end record",
                position
            );
        }

        end.zip64 = true;
        end.entryCount = zip64->entryCount;
        end.directorySize = zip64->directorySize;
        end.directoryOffset = zip64->directoryOffset;
        directoryEnd = zip64->start;
        recordPrefix = zip64->prefix;
    } else if (saturated) {
        return fail(ErrorKind::Malformed, "saturated end record without ZIP64 locator", position);
    } else if (disk != 0 || directoryDisk != 0 || entriesOnDisk != entryCount) {
        return fail(ErrorKind::Unsupported, "multi-disk archives are not supported", position);
    }

    if (end.directorySize > directoryEnd) {
        return fail(ErrorKind::Malformed, "central directory larger than the file", position);
    }

    auto directoryStart = directoryEnd - end.directorySize;
    if (end.directoryOffset > directoryStart) {
        return fail(ErrorKind::Malformed, "central directory offset beyond its location", position);
    }

    end.prefix = directoryStart - end.directoryOffset;
    if (recordPrefix && *recordPrefix != end.prefix) {
        return fail(ErrorKind::Malformed, "ZIP64 locator inconsistent with prefix", position);
    }
    if (end.entryCount > limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "entry count exceeds limit", position);
    }
    if (end.directorySize > limits.maxCentralDirectoryBytes) {
        return fail(ErrorKind::LimitExceeded, "central directory exceeds limit", position);
    }

    auto minimumSize = checkedMul(end.entryCount, centralHeaderSize);
    if (!minimumSize || *minimumSize > end.directorySize) {
        return fail(ErrorKind::Malformed, "entry count does not fit central directory", position);
    }

    if (end.directorySize > 0) {
        auto signature = readSignatureAt(file, directoryStart, centralHeaderSignature);
        if (!signature) {
            return tl::unexpected<Error>(signature.error());
        }
        if (!*signature) {
            return fail(ErrorKind::Malformed, "no central directory at computed offset", position);
        }
    }
    return end;
}

}

Result<std::string_view> nameAsUtf8(const Entry& entry, std::string& storage) {
    if (entry.utf8Name() || std::ranges::all_of(entry.name, [](char byte) {
            return static_cast<unsigned char>(byte) < 0x80;
        })) {
        return entry.name;
    }

    std::size_t outputSize = 0;
    for (char raw : entry.name) {
        auto byte = static_cast<unsigned char>(raw);
        outputSize += utf8Length(cp437CodePoint(byte));
    }

    storage.clear();
    storage.reserve(outputSize);
    for (char raw : entry.name) {
        auto byte = static_cast<unsigned char>(raw);
        appendUtf8(cp437CodePoint(byte), storage);
    }
    return storage;
}

Result<Reader> Reader::open(File file, const Limits& limits) {
    auto fileSize = file.size();
    if (!fileSize) {
        return tl::unexpected<Error>(fileSize.error());
    }
    if (*fileSize < endRecordSize) {
        return fail(ErrorKind::Malformed, "file too small to be a ZIP archive");
    }

    auto tailSize = static_cast<std::size_t>(std::min<std::uint64_t>(*fileSize, maxEndSearch));
    auto tailOffset = *fileSize - tailSize;
    std::vector<std::byte> tail(tailSize);
    auto read = file.readExactAt(tailOffset, tail);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }

    std::optional<EndRecord> found;
    std::size_t foundAt = 0;
    std::optional<Error> firstError;
    for (std::size_t at = tailSize - endRecordSize + 1; at-- > 0;) {
        if (!hasSignature(tail, at, endRecordSignature) || !reachesEnd(tail, at)) {
            continue;
        }

        auto candidate = readEndRecord(file, tail, at, tailOffset, limits);
        if (!candidate) {
            if (!firstError) {
                firstError = candidate.error();
            }
            continue;
        }
        if (found) {
            return fail(
                ErrorKind::Malformed,
                "ambiguous end of central directory",
                tailOffset + at
            );
        }

        found = *candidate;
        foundAt = at;
    }

    if (!found) {
        if (firstError) {
            return tl::unexpected<Error>(*firstError);
        }
        return fail(ErrorKind::Malformed, "end of central directory not found");
    }

    Reader reader(std::move(file));
    reader.directorySize_ = static_cast<std::size_t>(found->directorySize);
    reader.directoryOffset_ = found->directoryOffset;
    reader.entryCount_ = found->entryCount;
    reader.prefix_ = found->prefix;
    reader.maxNameLength_ = limits.maxNameLength;
    reader.zip64_ = found->zip64;

    reader.buffer_.resize(reader.directorySize_ + found->commentLength);
    auto directory = std::span(reader.buffer_).first(reader.directorySize_);
    auto directoryRead =
        reader.file_.readExactAt(found->prefix + found->directoryOffset, directory);
    if (!directoryRead) {
        return tl::unexpected<Error>(directoryRead.error());
    }

    auto comment = std::span<const std::byte>(tail).subspan(foundAt + endRecordSize);
    std::ranges::copy(
        comment,
        reader.buffer_.begin() + static_cast<std::ptrdiff_t>(reader.directorySize_)
    );

    auto cursor = reader.entries();
    Entry entry;
    while (true) {
        auto more = cursor.next(entry);
        if (!more) {
            return tl::unexpected<Error>(more.error());
        }
        if (!*more) {
            break;
        }
    }
    return reader;
}

std::string_view Reader::comment() const {
    auto bytes = std::span(buffer_).subspan(directorySize_);
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

Cursor Reader::entries() const {
    return Cursor(
        std::span(buffer_).first(directorySize_),
        prefix_ + directoryOffset_,
        directoryOffset_,
        maxNameLength_,
        entryCount_
    );
}

Result<std::uint64_t> Reader::dataOffset(const Entry& entry) const {
    auto directoryStart = prefix_ + directoryOffset_;
    auto shifted = checkedAdd(prefix_, entry.localHeaderOffset);
    auto headerOffset = shifted.value_or(directoryStart);
    if (!shifted || !fitsWithin(headerOffset, localHeaderSize, directoryStart)) {
        return fail(ErrorKind::Malformed, "local header outside the data area", headerOffset);
    }

    std::array<std::byte, localHeaderSize> header{};
    auto read = file_.readExactAt(headerOffset, header);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    if (loadLe<std::uint32_t>(header.data()) != localHeaderSignature) {
        return fail(ErrorKind::Malformed, "bad local header signature", headerOffset);
    }

    auto flags = loadLe<std::uint16_t>(header.data() + 6);
    auto method = loadLe<std::uint16_t>(header.data() + 8);
    auto crc = loadLe<std::uint32_t>(header.data() + 14);
    auto compressedSize = loadLe<std::uint32_t>(header.data() + 18);
    auto uncompressedSize = loadLe<std::uint32_t>(header.data() + 22);
    auto nameLength = loadLe<std::uint16_t>(header.data() + 26);
    auto extraLength = loadLe<std::uint16_t>(header.data() + 28);

    auto dataStart = headerOffset + localHeaderSize + nameLength + extraLength;
    if (dataStart > directoryStart) {
        return fail(ErrorKind::Truncated, "local header overruns the data area", headerOffset);
    }
    if (((flags | entry.flags) & flagStrongEncryption) != 0) {
        return fail(ErrorKind::Unsupported, "strong encryption is not supported", headerOffset);
    }
    if (method != entry.method) {
        return fail(ErrorKind::Malformed, "local header method differs from central", headerOffset);
    }
    if (((flags ^ entry.flags) & flagEncrypted) != 0) {
        return fail(ErrorKind::Malformed, "local header flags differ from central", headerOffset);
    }
    if (nameLength != entry.name.size()) {
        return fail(ErrorKind::Malformed, "local header name differs from central", headerOffset);
    }

    std::array<std::byte, 256> name{};
    std::size_t compared = 0;
    while (compared < nameLength) {
        auto chunk = std::span(name).first(std::min(name.size(), nameLength - compared));
        auto nameRead = file_.readExactAt(headerOffset + localHeaderSize + compared, chunk);
        if (!nameRead) {
            return tl::unexpected<Error>(nameRead.error());
        }
        if (std::memcmp(chunk.data(), entry.name.data() + compared, chunk.size()) != 0) {
            return fail(
                ErrorKind::Malformed,
                "local header name differs from central",
                headerOffset
            );
        }
        compared += chunk.size();
    }

    if (!entry.hasDataDescriptor()) {
        bool sizesAgree =
            (compressedSize == saturated32 || compressedSize == entry.compressedSize) &&
            (uncompressedSize == saturated32 || uncompressedSize == entry.uncompressedSize);
        if (crc != entry.crc32 || !sizesAgree) {
            return fail(ErrorKind::Malformed, "local header disagrees with central", headerOffset);
        }
    }

    if (!fitsWithin(dataStart, entry.compressedSize, directoryStart)) {
        return fail(ErrorKind::Malformed, "entry data overruns the data area", dataStart);
    }
    return dataStart;
}

Result<Reader::EntryStream> Reader::beginEntry(const Entry& entry, std::span<std::byte> scratch) {
    if (entry.encrypted()) {
        return fail(ErrorKind::Unsupported, "encrypted entries are not supported");
    }

    EntryStream stream;
    if (entry.method == methodStored) {
        if (entry.compressedSize != entry.uncompressedSize) {
            return fail(ErrorKind::Malformed, "stored entry sizes differ");
        }
        if (scratch.empty() && entry.uncompressedSize != 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }
        stream.input = scratch;
    } else if (entry.method == methodDeflate) {
        if (scratch.size() < 2) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer too small for deflate");
        }

        if (inflater_) {
            auto reset = inflater_->reset();
            if (!reset) {
                return tl::unexpected<Error>(reset.error());
            }
        } else {
            auto created = Inflater::create();
            if (!created) {
                return tl::unexpected<Error>(created.error());
            }
            inflater_.emplace(std::move(*created));
        }

        stream.inflater = &*inflater_;

        stream.input = scratch.first(scratch.size() / 2);
        stream.output = scratch.subspan(scratch.size() / 2);
    } else {
        return fail(ErrorKind::Unsupported, "compression method is not supported");
    }

    auto offset = dataOffset(entry);
    if (!offset) {
        return tl::unexpected<Error>(offset.error());
    }

    stream.dataStart = *offset;
    stream.position = *offset;
    stream.inputLeft = entry.compressedSize;
    stream.outputLeft = entry.uncompressedSize;
    stream.expectedCrc = entry.crc32;
    stream.method = entry.method;
    return stream;
}

Result<std::span<const std::byte>> Reader::nextChunk(EntryStream& stream) {
    if (stream.done) {
        return std::span<const std::byte>{};
    }
    if (stream.method == methodStored) {
        return nextStored(stream);
    }
    return nextDeflated(stream);
}

Result<std::span<const std::byte>> Reader::nextStored(EntryStream& stream) {
    if (stream.outputLeft == 0) {
        stream.inputLeft = 0;
        return finishEntry(stream);
    }

    auto chunk = stream.input.first(
        static_cast<std::size_t>(std::min<std::uint64_t>(stream.outputLeft, stream.input.size()))
    );
    auto read = file_.readExactAt(stream.position, chunk);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }

    stream.position += chunk.size();
    stream.outputLeft -= chunk.size();
    stream.crc.update(chunk);
    return std::span<const std::byte>(chunk);
}

Result<std::span<const std::byte>> Reader::nextDeflated(EntryStream& stream) {
    if (stream.streamEnded) {
        return finishEntry(stream);
    }

    while (true) {
        if (stream.pending.empty() && stream.inputLeft > 0) {
            auto chunk = stream.input.first(
                static_cast<std::size_t>(
                    std::min<std::uint64_t>(stream.inputLeft, stream.input.size())
                )
            );
            auto read = file_.readExactAt(stream.position, chunk);
            if (!read) {
                return tl::unexpected<Error>(read.error());
            }

            stream.pending = chunk;
            stream.position += chunk.size();
            stream.inputLeft -= chunk.size();
        }

        auto window = stream.outputLeft == 0
            ? stream.output.first(1)
            : stream.output.first(
                  static_cast<std::size_t>(
                      std::min<std::uint64_t>(stream.outputLeft, stream.output.size())
                  )
              );
        auto step = stream.inflater->decompress(stream.pending, window);
        if (!step) {
            auto error = step.error();
            error.offset = stream.dataStart;
            return tl::unexpected<Error>(error);
        }

        stream.pending = stream.pending.subspan(step->consumed);
        if (step->produced > stream.outputLeft) {
            return fail(
                ErrorKind::LimitExceeded,
                "deflate entry exceeds declared size",
                stream.dataStart
            );
        }

        stream.streamEnded = step->finished;
        if (step->produced > 0) {
            auto chunk = window.first(step->produced);
            stream.outputLeft -= chunk.size();
            stream.crc.update(chunk);
            return std::span<const std::byte>(chunk);
        }
        if (step->finished) {
            return finishEntry(stream);
        }
        if (step->consumed == 0) {
            if (stream.pending.empty() && stream.inputLeft == 0) {
                return fail(ErrorKind::Truncated, "deflate stream truncated", stream.dataStart);
            }
            return fail(ErrorKind::Malformed, "deflate decoder made no progress", stream.dataStart);
        }
    }
}

Result<std::span<const std::byte>> Reader::finishEntry(EntryStream& stream) {
    stream.done = true;
    if (stream.outputLeft != 0) {
        return fail(
            ErrorKind::Malformed,
            "deflate entry shorter than declared size",
            stream.dataStart
        );
    }
    if (!stream.pending.empty() || stream.inputLeft != 0) {
        return fail(ErrorKind::Malformed, "trailing data after deflate stream", stream.dataStart);
    }
    if (stream.crc.value() != stream.expectedCrc) {
        return fail(ErrorKind::Integrity, "entry CRC-32 mismatch", stream.dataStart);
    }
    return std::span<const std::byte>{};
}

bool looksLikeZip(std::span<const std::byte> head, std::span<const std::byte> tail) {
    if (hasSignature(head, 0, localHeaderSignature)) {
        return true;
    }
    if (tail.size() < endRecordSize) {
        return false;
    }

    tail = tail.last(std::min(tail.size(), maxEndSearch));
    for (std::size_t at = tail.size() - endRecordSize + 1; at-- > 0;) {
        if (hasSignature(tail, at, endRecordSignature) && reachesEnd(tail, at)) {
            return true;
        }
    }
    return false;
}

}
