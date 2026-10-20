#include "formats/cpio/header.hpp"

#include "base/checked.hpp"

namespace bale::cpio {

namespace {

constexpr std::uint32_t fileTypeMask = 0170000;
constexpr std::uint32_t socketType = 0140000;
constexpr std::uint32_t symlinkType = 0120000;
constexpr std::uint32_t regularType = 0100000;
constexpr std::uint32_t blockType = 0060000;
constexpr std::uint32_t directoryType = 0040000;
constexpr std::uint32_t charType = 0020000;
constexpr std::uint32_t fifoType = 0010000;

Result<std::uint64_t> parseHex(std::span<const std::byte> field, std::uint64_t at) {
    std::uint64_t value = 0;
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
            return fail(ErrorKind::Malformed, "invalid cpio hex field", at);
        }

        if (value > (0xFFFFFFFFFFFFFFFFULL >> 4)) {
            return fail(ErrorKind::Malformed, "cpio numeric field overflows", at);
        }
        value = (value << 4) | nibble;
    }
    return value;
}

EntryKind entryKind(std::uint32_t mode) {
    switch (mode & fileTypeMask) {
    case regularType:
        return EntryKind::Regular;
    case directoryType:
        return EntryKind::Directory;
    case symlinkType:
        return EntryKind::Symlink;
    case blockType:
        return EntryKind::BlockDevice;
    case charType:
        return EntryKind::CharDevice;
    case fifoType:
        return EntryKind::Fifo;
    case socketType:
        return EntryKind::Socket;
    default:
        return EntryKind::Other;
    }
}

}

bool looksLikeCpio(std::span<const std::byte> head) {
    if (head.size() < newcMagic.size()) {
        return false;
    }

    std::string_view magic(reinterpret_cast<const char*>(head.data()), newcMagic.size());
    return magic == newcMagic || magic == crcMagic;
}

Result<Header> parseHeader(
    std::span<const std::byte, headerSize> header,
    std::string_view name,
    std::uint64_t offset,
    std::uint64_t dataOffset
) {
    auto body = std::span<const std::byte>(header);
    std::string_view magic(reinterpret_cast<const char*>(body.data()), magicLength);
    if (magic != newcMagic && magic != crcMagic) {
        return fail(ErrorKind::Malformed, "unknown cpio magic", offset);
    }

    auto field = [&](std::size_t at) {
        return parseHex(body.subspan(at, fieldLength), offset + at);
    };

    auto ino = field(inoOffset);
    if (!ino) {
        return std::unexpected(ino.error());
    }

    auto mode = field(modeOffset);
    if (!mode) {
        return std::unexpected(mode.error());
    }

    auto uid = field(uidOffset);
    if (!uid) {
        return std::unexpected(uid.error());
    }

    auto gid = field(gidOffset);
    if (!gid) {
        return std::unexpected(gid.error());
    }

    auto nlink = field(nlinkOffset);
    if (!nlink) {
        return std::unexpected(nlink.error());
    }

    auto mtime = field(mtimeOffset);
    if (!mtime) {
        return std::unexpected(mtime.error());
    }

    auto filesize = field(filesizeOffset);
    if (!filesize) {
        return std::unexpected(filesize.error());
    }

    auto devMajor = field(devMajorOffset);
    if (!devMajor) {
        return std::unexpected(devMajor.error());
    }

    auto devMinor = field(devMinorOffset);
    if (!devMinor) {
        return std::unexpected(devMinor.error());
    }

    auto rdevMajor = field(rdevMajorOffset);
    if (!rdevMajor) {
        return std::unexpected(rdevMajor.error());
    }

    auto rdevMinor = field(rdevMinorOffset);
    if (!rdevMinor) {
        return std::unexpected(rdevMinor.error());
    }

    auto check = field(checkOffset);
    if (!check) {
        return std::unexpected(check.error());
    }

    auto narrowed =
        [&](std::uint64_t value, std::size_t at, const char* what) -> Result<std::uint32_t> {
        auto cast = checkedCast<std::uint32_t>(value);
        if (!cast) {
            return fail(ErrorKind::Malformed, what, offset + at);
        }
        return *cast;
    };

    auto fileMode = narrowed(*mode, modeOffset, "cpio mode out of range");
    if (!fileMode) {
        return std::unexpected(fileMode.error());
    }

    auto checksum = narrowed(*check, checkOffset, "cpio checksum out of range");
    if (!checksum) {
        return std::unexpected(checksum.error());
    }

    auto major = narrowed(*rdevMajor, rdevMajorOffset, "cpio device number out of range");
    if (!major) {
        return std::unexpected(major.error());
    }

    auto minor = narrowed(*rdevMinor, rdevMinorOffset, "cpio device number out of range");
    if (!minor) {
        return std::unexpected(minor.error());
    }

    auto filesystemMajor = narrowed(*devMajor, devMajorOffset, "cpio device number out of range");
    if (!filesystemMajor) {
        return std::unexpected(filesystemMajor.error());
    }

    auto filesystemMinor = narrowed(*devMinor, devMinorOffset, "cpio device number out of range");
    if (!filesystemMinor) {
        return std::unexpected(filesystemMinor.error());
    }

    auto seconds = checkedCast<std::int64_t>(*mtime);
    if (!seconds) {
        return fail(ErrorKind::Malformed, "cpio timestamp out of range", offset + mtimeOffset);
    }

    Header parsed;
    parsed.name = name;
    parsed.dataOffset = dataOffset;
    parsed.size = *filesize;
    parsed.ino = *ino;
    parsed.nlink = *nlink;
    parsed.uid = *uid;
    parsed.gid = *gid;
    parsed.mtimeSeconds = *seconds;
    parsed.mode = *fileMode;
    parsed.fsMajor = *filesystemMajor;
    parsed.fsMinor = *filesystemMinor;
    parsed.devMajor = *major;
    parsed.devMinor = *minor;
    parsed.check = *checksum;
    parsed.checksum = magic == crcMagic;
    parsed.kind = entryKind(*fileMode);
    parsed.trailer = name == trailerName;
    return parsed;
}

std::uint64_t namePadding(std::uint64_t namesize) {
    return (4 - (headerSize + namesize) % 4) % 4;
}

std::uint64_t dataPadding(std::uint64_t size) {
    return (4 - size % 4) % 4;
}

}
