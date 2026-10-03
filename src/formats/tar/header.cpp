#include "formats/tar/header.hpp"

#include "base/checked.hpp"

#include <algorithm>
#include <limits>

namespace bale::tar {

namespace {

struct Field {
    std::size_t offset;
    std::size_t length;
};

constexpr Field nameField{0, 100};
constexpr Field modeField{100, 8};
constexpr Field uidField{108, 8};
constexpr Field gidField{116, 8};
constexpr Field sizeField{124, 12};
constexpr Field mtimeField{136, 12};
constexpr Field checksumField{148, 8};
constexpr std::size_t typeflagOffset = 156;
constexpr Field linkNameField{157, 100};
constexpr Field magicField{257, 8};
constexpr Field unameField{265, 32};
constexpr Field gnameField{297, 32};
constexpr Field devMajorField{329, 8};
constexpr Field devMinorField{337, 8};
constexpr Field prefixField{345, 155};

constexpr std::string_view ustarMagic{
    "ustar\0"
    "00",
    8
};
constexpr std::string_view gnuMagic{"ustar  \0", 8};

std::span<const std::byte> bytesOf(Block block, Field field) {
    return block.subspan(field.offset, field.length);
}

std::string_view textOf(Block block, Field field) {
    auto bytes = bytesOf(block, field);
    std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return text.substr(0, text.find('\0'));
}

bool isOctalDigit(std::byte value) {
    return value >= std::byte{'0'} && value <= std::byte{'7'};
}

bool isDecimalDigit(char value) {
    return value >= '0' && value <= '9';
}

Result<std::uint64_t> parseOctal(std::span<const std::byte> field, std::uint64_t offset) {
    std::size_t index = 0;
    while (index < field.size() && field[index] == std::byte{' '}) {
        ++index;
    }

    std::uint64_t value = 0;
    for (; index < field.size() && isOctalDigit(field[index]); ++index) {
        if (value > (std::numeric_limits<std::uint64_t>::max() >> 3)) {
            return fail(ErrorKind::Malformed, "tar numeric field overflows", offset);
        }
        value = (value << 3) | (std::to_integer<std::uint64_t>(field[index]) - '0');
    }

    for (; index < field.size(); ++index) {
        if (field[index] != std::byte{0} && field[index] != std::byte{' '}) {
            return fail(ErrorKind::Malformed, "invalid tar octal field", offset);
        }
    }
    return value;
}

Result<std::uint64_t> parseBase256(std::span<const std::byte> field, std::uint64_t offset) {
    auto first = std::to_integer<std::uint8_t>(field[0]);
    if ((first & 0x40U) != 0) {
        return fail(ErrorKind::Malformed, "negative tar numeric field", offset);
    }

    std::uint64_t value = first & 0x3FU;
    for (auto byte : field.subspan(1)) {
        if (value > (std::numeric_limits<std::uint64_t>::max() >> 8)) {
            return fail(ErrorKind::Malformed, "tar numeric field overflows", offset);
        }
        value = (value << 8) | std::to_integer<std::uint64_t>(byte);
    }
    return value;
}

bool checksumMatches(Block block) {
    auto stored = parseOctal(bytesOf(block, checksumField), 0);
    if (!stored) {
        return false;
    }

    std::uint64_t unsignedSum = 0;
    std::int64_t signedSum = 0;
    for (std::size_t index = 0; index < block.size(); ++index) {
        auto byte = block[index];
        if (index >= checksumField.offset && index < checksumField.offset + checksumField.length) {
            byte = std::byte{' '};
        }
        unsignedSum += std::to_integer<std::uint8_t>(byte);
        signedSum += static_cast<std::int8_t>(std::to_integer<std::uint8_t>(byte));
    }

    if (*stored == unsignedSum) {
        return true;
    }
    return signedSum >= 0 && *stored == static_cast<std::uint64_t>(signedSum);
}

Result<Format> detectFormat(Block block, std::uint64_t offset) {
    auto magic = bytesOf(block, magicField);
    std::string_view text(reinterpret_cast<const char*>(magic.data()), magic.size());
    if (text == ustarMagic) {
        return Format::Ustar;
    }
    if (text == gnuMagic) {
        return Format::Gnu;
    }

    auto blank = std::ranges::all_of(magic, [](std::byte value) {
        return value == std::byte{0};
    });
    if (blank) {
        return Format::V7;
    }
    return fail(ErrorKind::Malformed, "unknown tar magic", offset + magicField.offset);
}

template <std::integral T> Result<T> parseField(Block block, Field field, std::uint64_t offset) {
    auto fieldOffset = offset + field.offset;
    auto value = parseNumber(bytesOf(block, field), fieldOffset);
    if (!value) {
        return std::unexpected(value.error());
    }

    auto narrowed = checkedCast<T>(*value);
    if (!narrowed) {
        return fail(ErrorKind::Malformed, "tar numeric field out of range", fieldOffset);
    }
    return *narrowed;
}

Result<std::uint64_t> parseDecimal(std::string_view text, std::uint64_t offset) {
    if (text.empty()) {
        return fail(ErrorKind::Malformed, "empty pax number", offset);
    }

    std::uint64_t value = 0;
    for (char digit : text) {
        if (!isDecimalDigit(digit)) {
            return fail(ErrorKind::Malformed, "invalid pax number", offset);
        }

        auto scaled = checkedMul<std::uint64_t>(value, 10);
        if (!scaled) {
            return fail(ErrorKind::Malformed, "pax number overflows", offset);
        }

        auto next = checkedAdd<std::uint64_t>(*scaled, static_cast<std::uint64_t>(digit - '0'));
        if (!next) {
            return fail(ErrorKind::Malformed, "pax number overflows", offset);
        }
        value = *next;
    }
    return value;
}

Result<void> parsePaxTime(std::string_view text, std::uint64_t offset, PaxValues& values) {
    bool negative = text.starts_with('-');
    if (negative) {
        text.remove_prefix(1);
    }

    auto dot = text.find('.');
    auto whole = parseDecimal(text.substr(0, dot), offset);
    if (!whole) {
        return std::unexpected(whole.error());
    }

    auto seconds = checkedCast<std::int64_t>(*whole);
    if (!seconds) {
        return fail(ErrorKind::Malformed, "pax mtime out of range", offset);
    }

    std::uint32_t nanoseconds = 0;
    if (dot != std::string_view::npos) {
        auto fraction = text.substr(dot + 1);
        if (fraction.empty()) {
            return fail(ErrorKind::Malformed, "invalid pax mtime fraction", offset);
        }

        std::uint32_t scale = 100'000'000;
        for (char digit : fraction) {
            if (!isDecimalDigit(digit)) {
                return fail(ErrorKind::Malformed, "invalid pax mtime fraction", offset);
            }
            nanoseconds += static_cast<std::uint32_t>(digit - '0') * scale;
            scale /= 10;
        }
    }

    if (negative && nanoseconds != 0) {
        values.mtimeSeconds = -*seconds - 1;
        values.mtimeNanoseconds = 1'000'000'000U - nanoseconds;
    } else {
        values.mtimeSeconds = negative ? -*seconds : *seconds;
        values.mtimeNanoseconds = nanoseconds;
    }
    values.hasMtime = true;
    return {};
}

Result<void> assignPath(
    std::string_view value,
    std::uint64_t offset,
    const Limits& limits,
    std::string& target,
    bool& present
) {
    if (value.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::Malformed, "pax path contains NUL", offset);
    }
    if (value.size() > limits.maxPathBytes) {
        return fail(ErrorKind::LimitExceeded, "pax path exceeds limit", offset);
    }

    target.assign(value);
    present = !value.empty();
    return {};
}

Result<void>
assignNumber(std::string_view value, std::uint64_t offset, std::uint64_t& target, bool& present) {
    if (value.empty()) {
        present = false;
        return {};
    }

    auto number = parseDecimal(value, offset);
    if (!number) {
        return std::unexpected(number.error());
    }

    target = *number;
    present = true;
    return {};
}

Result<void> applyPaxRecord(
    std::string_view key,
    std::string_view value,
    std::uint64_t offset,
    const Limits& limits,
    PaxValues& values
) {
    if (key.starts_with("GNU.sparse.")) {
        return fail(ErrorKind::Unsupported, "GNU sparse tar entries are not supported", offset);
    }

    if (key == "path") {
        return assignPath(value, offset, limits, values.path, values.hasPath);
    }
    if (key == "linkpath") {
        return assignPath(value, offset, limits, values.linkPath, values.hasLinkPath);
    }
    if (key == "size") {
        return assignNumber(value, offset, values.size, values.hasSize);
    }
    if (key == "uid") {
        return assignNumber(value, offset, values.uid, values.hasUid);
    }
    if (key == "gid") {
        return assignNumber(value, offset, values.gid, values.hasGid);
    }
    if (key == "uname") {
        values.uname.assign(value);
        values.hasUname = !value.empty();
        return {};
    }
    if (key == "gname") {
        values.gname.assign(value);
        values.hasGname = !value.empty();
        return {};
    }
    if (key == "mtime") {
        if (value.empty()) {
            values.hasMtime = false;
            return {};
        }
        return parsePaxTime(value, offset, values);
    }
    return {};
}

}

void PaxValues::clear() {
    hasPath = false;
    hasLinkPath = false;
    hasUname = false;
    hasGname = false;
    hasSize = false;
    hasUid = false;
    hasGid = false;
    hasMtime = false;
}

bool PaxValues::empty() const {
    return !hasPath && !hasLinkPath && !hasUname && !hasGname && !hasSize && !hasUid && !hasGid &&
        !hasMtime;
}

bool isZeroBlock(Block block) {
    return std::ranges::all_of(block, [](std::byte value) {
        return value == std::byte{0};
    });
}

bool looksLikeTar(Block firstBlock) {
    if (isZeroBlock(firstBlock)) {
        return false;
    }
    return parseHeader(firstBlock, 0).has_value();
}

Result<std::uint64_t> parseNumber(std::span<const std::byte> field, std::uint64_t offset) {
    if (!field.empty() && (std::to_integer<std::uint8_t>(field[0]) & 0x80U) != 0) {
        return parseBase256(field, offset);
    }
    return parseOctal(field, offset);
}

Result<Header> parseHeader(Block block, std::uint64_t offset) {
    if (!checksumMatches(block)) {
        return fail(ErrorKind::Integrity, "tar header checksum mismatch", offset);
    }

    auto format = detectFormat(block, offset);
    if (!format) {
        return std::unexpected(format.error());
    }

    Header header;
    header.format = *format;
    header.typeflag = static_cast<char>(block[typeflagOffset]);
    header.name = textOf(block, nameField);
    header.linkName = textOf(block, linkNameField);

    auto mode = parseField<std::uint32_t>(block, modeField, offset);
    if (!mode) {
        return std::unexpected(mode.error());
    }

    auto uid = parseField<std::uint64_t>(block, uidField, offset);
    if (!uid) {
        return std::unexpected(uid.error());
    }

    auto gid = parseField<std::uint64_t>(block, gidField, offset);
    if (!gid) {
        return std::unexpected(gid.error());
    }

    auto size = parseField<std::uint64_t>(block, sizeField, offset);
    if (!size) {
        return std::unexpected(size.error());
    }

    auto mtime = parseField<std::int64_t>(block, mtimeField, offset);
    if (!mtime) {
        return std::unexpected(mtime.error());
    }

    header.mode = *mode;
    header.uid = *uid;
    header.gid = *gid;
    header.size = *size;
    header.mtime = *mtime;

    if (header.format == Format::V7) {
        return header;
    }

    header.uname = textOf(block, unameField);
    header.gname = textOf(block, gnameField);
    if (header.format == Format::Ustar) {
        header.prefix = textOf(block, prefixField);
    }

    auto kind = entryKind(header.typeflag);
    if (kind == EntryKind::CharDevice || kind == EntryKind::BlockDevice) {
        auto major = parseField<std::uint32_t>(block, devMajorField, offset);
        if (!major) {
            return std::unexpected(major.error());
        }

        auto minor = parseField<std::uint32_t>(block, devMinorField, offset);
        if (!minor) {
            return std::unexpected(minor.error());
        }
        header.devMajor = *major;
        header.devMinor = *minor;
    }
    return header;
}

EntryKind entryKind(char typeflag) {
    switch (typeflag) {
    case '0':
    case '\0':
    case '7':
        return EntryKind::Regular;
    case '1':
        return EntryKind::HardLink;
    case '2':
        return EntryKind::Symlink;
    case '3':
        return EntryKind::CharDevice;
    case '4':
        return EntryKind::BlockDevice;
    case '5':
        return EntryKind::Directory;
    case '6':
        return EntryKind::Fifo;
    default:
        return EntryKind::Other;
    }
}

bool entryHasData(EntryKind kind) {
    switch (kind) {
    case EntryKind::HardLink:
    case EntryKind::Symlink:
    case EntryKind::CharDevice:
    case EntryKind::BlockDevice:
    case EntryKind::Fifo:
        return false;
    case EntryKind::Regular:
    case EntryKind::Directory:
    case EntryKind::Other:
        return true;
    }
    return true;
}

std::optional<std::uint64_t> paddedSize(std::uint64_t size) {
    auto rounded = checkedAdd<std::uint64_t>(size, blockSize - 1);
    if (!rounded) {
        return std::nullopt;
    }
    return *rounded & ~std::uint64_t{blockSize - 1};
}

Result<void> parsePaxRecords(
    std::string_view data,
    std::uint64_t offset,
    const Limits& limits,
    PaxValues& values
) {
    constexpr std::size_t maxLengthDigits = 19;

    std::size_t position = 0;
    while (position < data.size()) {
        auto recordOffset = offset + position;
        auto rest = data.substr(position);

        std::size_t digits = 0;
        std::uint64_t length = 0;
        while (digits < rest.size() && isDecimalDigit(rest[digits])) {
            if (digits == maxLengthDigits) {
                return fail(ErrorKind::Malformed, "pax record length too long", recordOffset);
            }
            length = length * 10 + static_cast<std::uint64_t>(rest[digits] - '0');
            ++digits;
        }

        if (digits == 0 || digits >= rest.size() || rest[digits] != ' ') {
            return fail(ErrorKind::Malformed, "malformed pax record length", recordOffset);
        }
        if (length > rest.size() || length < digits + 3) {
            return fail(ErrorKind::Malformed, "pax record length out of range", recordOffset);
        }

        auto recordLength = static_cast<std::size_t>(length);
        auto record = rest.substr(0, recordLength);
        if (record.back() != '\n') {
            return fail(ErrorKind::Malformed, "pax record not terminated by newline", recordOffset);
        }

        auto body = record.substr(digits + 1, recordLength - digits - 2);
        auto equals = body.find('=');
        if (equals == std::string_view::npos || equals == 0) {
            return fail(ErrorKind::Malformed, "pax record without key", recordOffset);
        }

        auto key = body.substr(0, equals);
        auto value = body.substr(equals + 1);
        auto applied = applyPaxRecord(key, value, recordOffset, limits, values);
        if (!applied) {
            return applied;
        }
        position += recordLength;
    }
    return {};
}

}
