#include "formats/gzip/header.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "io/byte_reader.hpp"

#include <algorithm>

namespace bale::gzip {

namespace {

constexpr std::byte magic1{0x1f};
constexpr std::byte magic2{0x8b};
constexpr std::uint8_t methodDeflate = 8;
constexpr std::uint8_t reservedFlags = 0xE0;

Result<std::string_view>
readTerminated(ByteReader& reader, std::size_t limit, std::string_view tooLong) {
    auto rest = reader.rest();
    std::size_t searchLength = rest.size();
    if (limit < rest.size()) {
        searchLength = limit + 1;
    }

    auto searched = rest.first(searchLength);
    auto end = std::ranges::find(searched, std::byte{0});
    if (end == searched.end()) {
        if (rest.size() > limit) {
            return fail(ErrorKind::LimitExceeded, tooLong, reader.offset());
        }
        return fail(ErrorKind::Truncated, "gzip header truncated", reader.offset());
    }

    auto length = static_cast<std::size_t>(end - searched.begin());
    std::string_view text(reinterpret_cast<const char*>(rest.data()), length);
    auto skipped = reader.skip(length + 1);
    if (!skipped) {
        return tl::unexpected<Error>(skipped.error());
    }
    return text;
}

}

Result<Header>
parseHeader(std::span<const std::byte> data, const Limits& limits, std::uint64_t offset) {
    if (data.size() < fixedHeaderSize) {
        return fail(ErrorKind::Truncated, "gzip header truncated", offset);
    }
    if (data[0] != magic1 || data[1] != magic2) {
        return fail(ErrorKind::Malformed, "not a gzip member", offset);
    }
    if (std::to_integer<std::uint8_t>(data[2]) != methodDeflate) {
        return fail(ErrorKind::Unsupported, "gzip compression method is not deflate", offset);
    }

    Header header;
    header.flags = std::to_integer<std::uint8_t>(data[3]);
    header.mtime = loadLe<std::uint32_t>(data.data() + 4);
    header.extraFlags = std::to_integer<std::uint8_t>(data[8]);
    header.os = std::to_integer<std::uint8_t>(data[9]);
    if ((header.flags & reservedFlags) != 0) {
        return fail(ErrorKind::Malformed, "reserved gzip flag bits set", offset);
    }

    ByteReader reader(data, offset);
    auto fixed = reader.skip(fixedHeaderSize);
    if (!fixed) {
        return tl::unexpected<Error>(fixed.error());
    }

    if ((header.flags & flagExtra) != 0) {
        auto length = reader.u16le();
        if (!length) {
            return fail(ErrorKind::Truncated, "gzip header truncated", reader.offset());
        }
        if (*length > limits.maxExtraBytes) {
            return fail(
                ErrorKind::LimitExceeded,
                "gzip extra field exceeds limit",
                reader.offset()
            );
        }

        auto extra = reader.bytes(*length);
        if (!extra) {
            return fail(ErrorKind::Truncated, "gzip header truncated", reader.offset());
        }
        header.extra = *extra;
    }

    if ((header.flags & flagName) != 0) {
        auto name = readTerminated(reader, limits.maxNameLength, "gzip file name exceeds limit");
        if (!name) {
            return tl::unexpected<Error>(name.error());
        }
        header.name = *name;
    }

    if ((header.flags & flagComment) != 0) {
        auto comment =
            readTerminated(reader, limits.maxCommentLength, "gzip comment exceeds limit");
        if (!comment) {
            return tl::unexpected<Error>(comment.error());
        }
        header.comment = *comment;
    }

    if ((header.flags & flagHeaderCrc) != 0) {
        auto covered = data.first(reader.position());
        auto stored = reader.u16le();
        if (!stored) {
            return fail(ErrorKind::Truncated, "gzip header truncated", reader.offset());
        }
        if (*stored != static_cast<std::uint16_t>(Crc32::of(covered) & 0xFFFF)) {
            return fail(ErrorKind::Integrity, "gzip header CRC-16 mismatch", offset);
        }
    }

    header.size = reader.position();
    return header;
}

Result<std::size_t> maxHeaderSize(const Limits& limits) {
    std::size_t total = fixedHeaderSize + 2 + 2 + 2;
    for (std::size_t part : {limits.maxExtraBytes, limits.maxNameLength, limits.maxCommentLength}) {
        auto sum = checkedAdd(total, part);
        if (!sum) {
            return fail(ErrorKind::LimitExceeded, "gzip header limits too large");
        }
        total = *sum;
    }
    return total;
}

bool looksLikeGzip(std::span<const std::byte> head) {
    return head.size() >= fixedHeaderSize && head[0] == magic1 && head[1] == magic2 &&
        std::to_integer<std::uint8_t>(head[2]) == methodDeflate &&
        (std::to_integer<std::uint8_t>(head[3]) & reservedFlags) == 0;
}

std::array<std::byte, fixedHeaderSize> encodeHeader(int compressionLevel) {
    constexpr std::uint8_t extraFlagsSlowest = 2;
    constexpr std::uint8_t extraFlagsFastest = 4;
    constexpr std::byte unknownOs{0xFF};

    std::uint8_t extraFlags = 0;
    if (compressionLevel == 9) {
        extraFlags = extraFlagsSlowest;
    } else if (compressionLevel == 1) {
        extraFlags = extraFlagsFastest;
    }

    std::array<std::byte, fixedHeaderSize> header{};
    header[0] = magic1;
    header[1] = magic2;
    header[2] = std::byte{methodDeflate};
    header[8] = std::byte{extraFlags};
    header[9] = unknownOs;
    return header;
}

std::array<std::byte, trailerSize> encodeTrailer(std::uint32_t crc, std::uint64_t size) {
    std::array<std::byte, trailerSize> trailer{};
    storeLe(trailer.data(), crc);
    storeLe(trailer.data() + 4, static_cast<std::uint32_t>(size));
    return trailer;
}

}
