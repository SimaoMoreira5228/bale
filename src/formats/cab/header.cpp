#include "formats/cab/header.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "io/file.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace bale::cab {

namespace {

constexpr std::size_t folderRecordSize = 8;
constexpr std::size_t fileRecordSize = 16;
constexpr std::size_t blockRecordSize = 8;
constexpr std::size_t reserveSizeBytes = 4;

Result<std::uint16_t> readU16(const File& file, std::uint64_t at) {
    std::array<std::byte, 2> bytes{};
    auto read = file.readExactAt(at, bytes);
    if (!read) {
        return std::unexpected(read.error());
    }
    return loadLe<std::uint16_t>(bytes.data());
}

Result<std::uint32_t> readU32(const File& file, std::uint64_t at) {
    std::array<std::byte, 4> bytes{};
    auto read = file.readExactAt(at, bytes);
    if (!read) {
        return std::unexpected(read.error());
    }
    return loadLe<std::uint32_t>(bytes.data());
}

Result<std::string> readLabel(
    const File& file,
    std::uint64_t& pos,
    std::uint64_t bound,
    const Limits& limits,
    const char* what
) {
    if (pos >= bound) {
        return fail(ErrorKind::Malformed, what, pos);
    }

    auto room = bound - pos;
    auto cap = std::min<std::uint64_t>(room, static_cast<std::uint64_t>(limits.maxNameBytes) + 1);
    std::string label(static_cast<std::size_t>(cap), '\0');
    auto read = file.readExactAt(pos, std::as_writable_bytes(std::span(label)));
    if (!read) {
        return std::unexpected(read.error());
    }

    auto end = label.find('\0');
    if (end == std::string::npos) {
        if (cap > limits.maxNameBytes) {
            return fail(ErrorKind::LimitExceeded, what, pos);
        }
        return fail(ErrorKind::Malformed, what, pos);
    }

    label.resize(end);
    auto next = checkedAdd(pos, end + 1);
    if (!next) {
        return fail(ErrorKind::Malformed, what, pos);
    }
    pos = *next;
    return label;
}

constexpr std::int64_t daysFromCivil(int year, int month, int day) noexcept {
    int adjusted = month <= 2 ? year - 1 : year;
    int era = (adjusted >= 0 ? adjusted : adjusted - 399) / 400;
    int yearOfEra = adjusted - era * 400;
    int monthOfYear = month > 2 ? month - 3 : month + 9;
    int dayOfYear = (153 * monthOfYear + 2) / 5 + day - 1;
    int dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
    return static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(dayOfEra) - 719468;
}

}

bool looksLikeCab(std::span<const std::byte> head) {
    return head.size() >= signature.size() &&
        std::ranges::equal(signature, head.first(signature.size()));
}

std::int64_t dosToUnix(std::uint16_t date, std::uint16_t time) {
    int month = (date >> 5) & 0x0F;
    int day = date & 0x1F;
    int hour = time >> 11;
    int minute = (time >> 5) & 0x3F;
    int second = (time & 0x1F) * 2;
    int year = 1980 + (date >> 9);

    // NOTE: timestamps are metadata; out-of-range fields collapse to the
    // epoch instead of rejecting an otherwise sound archive.
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
        return 0;
    }
    constexpr int monthDays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    int limit = monthDays[month - 1];
    bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    if (month == 2 && leap) {
        limit = 29;
    }
    if (day > limit) {
        return 0;
    }

    std::int64_t days = daysFromCivil(year, month, day);
    return days * 86400 + static_cast<std::int64_t>(hour * 3600 + minute * 60 + second);
}

Result<Model> parseCabinet(const File& file, std::uint64_t fileSize, const Limits& limits) {
    if (fileSize < headerBaseSize) {
        return fail(ErrorKind::Malformed, "not a cabinet archive");
    }

    std::array<std::byte, headerBaseSize> head{};
    auto headRead = file.readExactAt(0, head);
    if (!headRead) {
        return std::unexpected(headRead.error());
    }
    if (!looksLikeCab(head)) {
        return fail(ErrorKind::Malformed, "not a cabinet archive");
    }

    std::uint32_t cabinetBytes = loadLe<std::uint32_t>(head.data() + 8);
    std::uint32_t filesOffset = loadLe<std::uint32_t>(head.data() + 16);
    std::uint16_t folderCount = loadLe<std::uint16_t>(head.data() + 26);
    std::uint16_t fileCount = loadLe<std::uint16_t>(head.data() + 28);
    std::uint16_t flags = loadLe<std::uint16_t>(head.data() + 30);

    if (head[25] != std::byte{1}) {
        return fail(ErrorKind::Unsupported, "cabinet version is not supported", 25);
    }
    if (cabinetBytes < headerBaseSize) {
        return fail(ErrorKind::Malformed, "cabinet size is smaller than its header", 8);
    }
    if (cabinetBytes > fileSize) {
        return fail(ErrorKind::Truncated, "cabinet size extends past end of file", 8);
    }
    std::uint64_t image = cabinetBytes;

    if (fileCount > limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "cabinet entry count exceeds limit", 28);
    }

    auto position = std::uint64_t{headerBaseSize};
    std::uint64_t folderReserve = 0;
    std::uint64_t dataReserve = 0;
    if ((flags & flagReservePresent) != 0) {
        auto end = checkedAdd(position, reserveSizeBytes);
        if (!end || *end > image) {
            return fail(ErrorKind::Truncated, "cabinet header ends inside reserve sizes", position);
        }

        auto cabinetReserve = readU16(file, position);
        if (!cabinetReserve) {
            return std::unexpected(cabinetReserve.error());
        }
        std::array<std::byte, 2> sizes{};
        auto sizeRead = file.readExactAt(position + 2, sizes);
        if (!sizeRead) {
            return std::unexpected(sizeRead.error());
        }
        folderReserve = std::to_integer<std::uint8_t>(sizes[0]);
        dataReserve = std::to_integer<std::uint8_t>(sizes[1]);
        if (*cabinetReserve > limits.maxReserveBytes || folderReserve > limits.maxReserveBytes ||
            dataReserve > limits.maxReserveBytes) {
            return fail(ErrorKind::LimitExceeded, "cabinet reserve area exceeds limit", position);
        }

        position = *end + *cabinetReserve;
        if (position > image) {
            return fail(ErrorKind::Malformed, "cabinet reserve extends past end of image", 36);
        }
    }

    bool hasPrev = (flags & flagPrevCabinet) != 0;
    bool hasNext = (flags & flagNextCabinet) != 0;
    if (hasPrev) {
        auto prev = readLabel(file, position, image, limits, "cabinet set label is missing");
        if (!prev) {
            return std::unexpected(prev.error());
        }
        auto disk = readLabel(file, position, image, limits, "cabinet set label is missing");
        if (!disk) {
            return std::unexpected(disk.error());
        }
    }
    if (hasNext) {
        auto next = readLabel(file, position, image, limits, "cabinet set label is missing");
        if (!next) {
            return std::unexpected(next.error());
        }
        auto disk = readLabel(file, position, image, limits, "cabinet set label is missing");
        if (!disk) {
            return std::unexpected(disk.error());
        }
    }

    if (filesOffset < position || filesOffset > image) {
        return fail(ErrorKind::Malformed, "cabinet file table offset is out of range", 16);
    }

    Model model;
    model.imageBytes = image;
    model.hasPrev = hasPrev;
    model.hasNext = hasNext;

    std::uint64_t folderRecord = 8 + folderReserve;
    std::uint64_t usedEnd = filesOffset;
    for (std::uint16_t index = 0; index < folderCount; ++index) {
        auto at = checkedAdd(position, static_cast<std::uint64_t>(index) * folderRecord);
        if (!at) {
            return fail(ErrorKind::Malformed, "cabinet folder table overflows", position);
        }
        auto end = checkedAdd(*at, folderRecordSize);
        if (!end || *end > filesOffset) {
            return fail(ErrorKind::Malformed, "cabinet folder table runs into its file table", *at);
        }

        auto start = readU32(file, *at);
        if (!start) {
            return std::unexpected(start.error());
        }
        auto blocks = readU16(file, *at + 4);
        if (!blocks) {
            return std::unexpected(blocks.error());
        }
        auto type = readU16(file, *at + 6);
        if (!type) {
            return std::unexpected(type.error());
        }

        auto method = static_cast<std::uint16_t>(*type & 0x000F);
        if (method > methodLzx) {
            return fail(ErrorKind::Unsupported, "cabinet compression method is not supported", *at);
        }
        if (method == methodQuantum) {
            return fail(ErrorKind::Unsupported, "Quantum compression is not supported", *at);
        }
        if (*blocks == 0) {
            return fail(ErrorKind::Malformed, "cabinet folder has no data blocks", *at);
        }

        unsigned windowBits = (*type >> 8) & 0x1F;
        if (method == methodLzx && (windowBits < 15 || windowBits > 21)) {
            return fail(ErrorKind::Unsupported, "cabinet LZX window is not supported", *at);
        }

        model.folders.push_back(
            Folder{
                .dataOffset = *start,
                .uncompressedBytes = 0,
                .method = method,
                .windowBits = windowBits,
                .blocks = {},
            }
        );

        auto recordEnd = checkedAdd(*at, folderRecord);
        if (!recordEnd || *recordEnd > filesOffset) {
            return fail(ErrorKind::Malformed, "cabinet folder table runs into its file table", *at);
        }

        std::uint64_t cursor = *start;
        if (cursor < usedEnd) {
            return fail(ErrorKind::Malformed, "cabinet folder data overlaps earlier data", *at);
        }
        for (std::uint16_t block = 0; block < *blocks; ++block) {
            auto headerEnd = checkedAdd(cursor, blockRecordSize);
            if (!headerEnd) {
                return fail(ErrorKind::Malformed, "cabinet data block offset overflows", cursor);
            }

            auto payload = checkedAdd(*headerEnd, dataReserve);
            if (!payload) {
                return fail(ErrorKind::Malformed, "cabinet data block offset overflows", cursor);
            }

            std::array<std::byte, blockRecordSize> record{};
            auto recordRead = file.readExactAt(cursor, record);
            if (!recordRead) {
                return std::unexpected(recordRead.error());
            }

            std::uint32_t checksum = loadLe<std::uint32_t>(record.data());
            std::uint64_t compressed = loadLe<std::uint16_t>(record.data() + 4);
            std::uint64_t uncompressed = loadLe<std::uint16_t>(record.data() + 6);

            auto dataEnd = checkedAdd(*payload, compressed);
            if (!dataEnd || *dataEnd > image) {
                return fail(
                    ErrorKind::Malformed,
                    "cabinet data block extends past end of image",
                    cursor
                );
            }

            auto& folder = model.folders.back();
            if (cursor < filesOffset) {
                return fail(ErrorKind::Malformed, "cabinet data overlaps its file table", cursor);
            }
            if (!folder.blocks.empty()) {
                const DataBlock& prev = folder.blocks.back();
                auto prevEnd = checkedAdd(prev.payloadOffset, prev.compressedBytes);
                if (!prevEnd || cursor < *prevEnd) {
                    return fail(ErrorKind::Malformed, "cabinet data blocks overlap", cursor);
                }
            }

            auto total = checkedAdd(folder.uncompressedBytes, uncompressed);
            if (!total || *total > limits.maxFolderBytes) {
                return fail(ErrorKind::LimitExceeded, "cabinet folder exceeds size limit", cursor);
            }
            folder.uncompressedBytes = *total;

            folder.blocks.push_back(
                DataBlock{
                    .payloadOffset = *payload,
                    .checksum = checksum,
                    .compressedBytes = compressed,
                    .uncompressedBytes = uncompressed,
                }
            );
            cursor = *dataEnd;
        }
        usedEnd = cursor;
    }

    position = filesOffset;
    std::uint64_t totalBytes = 0;
    for (std::uint16_t index = 0; index < fileCount; ++index) {
        auto end = checkedAdd(position, fileRecordSize);
        if (!end || *end > image) {
            return fail(ErrorKind::Truncated, "cabinet ends inside a file record", position);
        }

        std::array<std::byte, fileRecordSize> record{};
        auto recordRead = file.readExactAt(position, record);
        if (!recordRead) {
            return std::unexpected(recordRead.error());
        }

        std::uint64_t size = loadLe<std::uint32_t>(record.data());
        std::uint64_t folderOffset = loadLe<std::uint32_t>(record.data() + 4);
        std::uint16_t folderIndex = loadLe<std::uint16_t>(record.data() + 8);
        std::uint16_t date = loadLe<std::uint16_t>(record.data() + 10);
        std::uint16_t time = loadLe<std::uint16_t>(record.data() + 12);
        std::uint16_t attribs = loadLe<std::uint16_t>(record.data() + 14);

        auto nameAt = *end;
        auto name = readLabel(file, nameAt, image, limits, "cabinet file name is missing");
        if (!name) {
            return std::unexpected(name.error());
        }
        if (name->empty()) {
            return fail(ErrorKind::Malformed, "cabinet file name is empty", position);
        }

        bool spanned = folderIndex >= folderContinuedFromPrev;
        if (!spanned && folderIndex >= model.folders.size()) {
            return fail(ErrorKind::Malformed, "cabinet file references no folder", position);
        }
        if (size > limits.maxEntryBytes) {
            return fail(ErrorKind::LimitExceeded, "cabinet entry exceeds size limit", position);
        }

        bool directory = (attribs & attribDirectory) != 0;
        if (!spanned && !directory) {
            const Folder& folder = model.folders[folderIndex];
            auto fileEnd = checkedAdd(folderOffset, size);
            if (!fileEnd || *fileEnd > folder.uncompressedBytes) {
                return fail(ErrorKind::Malformed, "cabinet file extends past its folder", position);
            }

            auto next = checkedAdd(totalBytes, size);
            if (!next || *next > limits.maxTotalBytes) {
                return fail(ErrorKind::LimitExceeded, "cabinet total size exceeds limit", position);
            }
            totalBytes = *next;
        }

        std::uint32_t mode = directory ? 040755U : 0100644U;
        if ((attribs & attribReadOnly) != 0) {
            mode &= ~static_cast<std::uint32_t>(0222);
        }

        model.names.push_back(std::move(*name));
        model.files.push_back(
            FileMeta{
                .name = {},
                .size = directory ? 0 : size,
                .folderOffset = folderOffset,
                .folder = folderIndex,
                .mtimeSeconds = dosToUnix(date, time),
                .mode = mode,
                .directory = directory,
                .spanned = spanned,
            }
        );
        position = nameAt;
    }

    // NOTE: names_ may have reallocated while indexing, which invalidates the
    // string_view names stored in files_, so rebind every view to its owner.
    for (std::size_t index = 0; index < model.files.size(); ++index) {
        model.files[index].name = model.names[index];
    }
    return model;
}

}
