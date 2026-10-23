#include "formats/wim/header.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <algorithm>
#include <array>

namespace bale::wim {

namespace {

[[nodiscard]] bool isPowerOfTwo(std::uint32_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

[[nodiscard]] Result<ResourceRef> parseReshdr(
    std::span<const std::byte, 24> raw,
    std::uint64_t fileSize,
    const char* what,
    bool allowEmpty
) {
    std::uint64_t size = 0;
    for (std::size_t index = 0; index < 7; ++index) {
        size |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(raw[index]))
            << (index * 8);
    }
    ResourceRef ref{
        .offset = loadLe<std::uint64_t>(raw.data() + 8),
        .sizeInWim = size,
        .uncompressed = loadLe<std::uint64_t>(raw.data() + 16),
        .flags = std::to_integer<std::uint8_t>(raw[7]),
    };
    if (size == 0 && ref.offset == 0 && ref.uncompressed == 0) {
        if (!allowEmpty) {
            return fail(ErrorKind::Malformed, what);
        }
        return ref;
    }
    if (!fitsWithin(ref.offset, ref.sizeInWim, fileSize)) {
        return fail(ErrorKind::Malformed, what);
    }
    return ref;
}

}

bool looksLikeWim(std::span<const std::byte> head) {
    return head.size() >= signature.size() &&
        std::ranges::equal(signature, head.first(signature.size()));
}

Result<Header> parseHeader(const File& file, std::uint64_t fileSize) {
    if (fileSize < headerDiskSize) {
        return fail(ErrorKind::Malformed, "not a WIM image");
    }

    std::array<std::byte, headerDiskSize> head{};
    auto read = file.readExactAt(0, head);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    if (!looksLikeWim(head)) {
        return fail(ErrorKind::Malformed, "not a WIM image");
    }

    std::uint32_t diskSize = loadLe<std::uint32_t>(head.data() + 8);
    if (diskSize != headerDiskSize) {
        return fail(ErrorKind::Unsupported, "unsupported WIM header size", 8);
    }
    std::uint32_t version = loadLe<std::uint32_t>(head.data() + 12);
    if (version != versionDefault && version != versionSolid) {
        return fail(ErrorKind::Unsupported, "unsupported WIM version", 12);
    }

    std::uint32_t flags = loadLe<std::uint32_t>(head.data() + 16);
    if ((flags & flagWriteInProgress) != 0) {
        return fail(ErrorKind::Malformed, "WIM was not closed cleanly", 16);
    }
    if ((flags & flagSpanned) != 0) {
        return fail(ErrorKind::Unsupported, "split WIM archives are not supported", 16);
    }

    std::uint32_t chunkSize = loadLe<std::uint32_t>(head.data() + 20);
    Compression compression = Compression::None;
    if ((flags & flagCompression) != 0) {
        std::uint32_t type =
            flags & (flagCompressXpress | flagCompressLzx | flagCompressLzms | flagCompressXpress2);
        if (type != flagCompressXpress && type != flagCompressLzx && type != flagCompressLzms &&
            type != flagCompressXpress2) {
            return fail(ErrorKind::Malformed, "WIM compression type is ambiguous", 16);
        }
        if (!isPowerOfTwo(chunkSize) || chunkSize > (std::uint32_t{1} << 31)) {
            return fail(ErrorKind::Malformed, "WIM chunk size is invalid", 20);
        }
        if (type == flagCompressXpress || type == flagCompressXpress2) {
            compression = Compression::Xpress;
        } else if (type == flagCompressLzx) {
            compression = Compression::Lzx;
        } else {
            compression = Compression::Lzms;
        }
    } else if (chunkSize != 0) {
        return fail(ErrorKind::Malformed, "uncompressed WIM names a chunk size", 20);
    }

    std::uint16_t part = loadLe<std::uint16_t>(head.data() + 40);
    std::uint16_t parts = loadLe<std::uint16_t>(head.data() + 42);
    if (part != 1 || parts != 1) {
        return fail(ErrorKind::Unsupported, "split WIM archives are not supported", 40);
    }

    std::uint32_t images = loadLe<std::uint32_t>(head.data() + 44);
    if (images == 0) {
        return fail(ErrorKind::Malformed, "WIM holds no images", 44);
    }

    Header header{
        .version = version,
        .compression = compression,
        .chunkSize = chunkSize,
        .imageCount = images,
        .bootIndex = 0,
        .lookup = {},
        .xml = {},
        .bootMeta = {},
    };

    auto lookup = parseReshdr(
        std::span<const std::byte, 24>(head.data() + 48, 24),
        fileSize,
        "WIM lookup table is out of range",
        false
    );
    if (!lookup) {
        return tl::unexpected<Error>(lookup.error());
    }
    header.lookup = *lookup;

    auto xml = parseReshdr(
        std::span<const std::byte, 24>(head.data() + 72, 24),
        fileSize,
        "WIM metadata XML is out of range",
        false
    );
    if (!xml) {
        return tl::unexpected<Error>(xml.error());
    }
    header.xml = *xml;

    auto boot = parseReshdr(
        std::span<const std::byte, 24>(head.data() + 96, 24),
        fileSize,
        "WIM boot metadata is out of range",
        true
    );
    if (!boot) {
        return tl::unexpected<Error>(boot.error());
    }
    header.bootMeta = *boot;

    header.bootIndex = loadLe<std::uint32_t>(head.data() + 120);
    if (header.bootIndex > images) {
        return fail(ErrorKind::Malformed, "WIM boot image index is out of range", 120);
    }
    return header;
}

std::string_view compressionName(Compression compression) {
    switch (compression) {
    case Compression::None:
        return "none";
    case Compression::Xpress:
        return "xpress";
    case Compression::Lzx:
        return "lzx";
    case Compression::Lzms:
        return "lzms";
    }
    return "unknown";
}

}
