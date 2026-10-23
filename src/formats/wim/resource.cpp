#include "formats/wim/resource.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <array>
#include <vector>

namespace bale::wim {

namespace {

inline constexpr std::uint64_t altTableHeaderSize = 16;

[[nodiscard]] bool isPowerOfTwo(std::uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

[[nodiscard]] Result<Compression> formatFromValue(std::uint32_t value, std::uint64_t at) {
    switch (value) {
    case 0:
        return Compression::None;
    case 1:
        return Compression::Xpress;
    case 2:
        return Compression::Lzx;
    case 3:
        return Compression::Lzms;
    default:
        break;
    }
    return fail(ErrorKind::Unsupported, "WIM solid compression format is not supported", at);
}

[[nodiscard]] Result<void> refuseFormat(Compression format, std::uint64_t at) {
    switch (format) {
    case Compression::None:
        return fail(ErrorKind::Malformed, "WIM chunk claims no compression", at);
    case Compression::Xpress:
        return fail(
            ErrorKind::Unsupported,
            "XPRESS-compressed WIM resources are not supported",
            at
        );
    case Compression::Lzx:
        return fail(ErrorKind::Unsupported, "LZX-compressed WIM resources are not supported", at);
    case Compression::Lzms:
        return fail(ErrorKind::Unsupported, "LZMS-compressed WIM resources are not supported", at);
    }
    return fail(ErrorKind::Unsupported, "WIM compression is not supported", at);
}

}

Result<Resource> Resource::open(
    const File& file,
    const ResourceRef& ref,
    const ResourceContext& context,
    const Limits& limits,
    std::uint64_t capBytes
) {
    if (!fitsWithin(ref.offset, ref.sizeInWim, context.fileSize)) {
        return fail(ErrorKind::Malformed, "WIM resource is out of range", ref.offset);
    }
    if ((ref.flags & resFlagSpanned) != 0) {
        return fail(ErrorKind::Unsupported, "split WIM archives are not supported", ref.offset);
    }
    if (ref.uncompressed == 0) {
        if (ref.sizeInWim != 0) {
            return fail(ErrorKind::Malformed, "WIM resource size mismatch", ref.offset);
        }
        return Resource(&file, ref, &limits);
    }
    if (ref.uncompressed > capBytes) {
        return fail(ErrorKind::LimitExceeded, "WIM resource exceeds size limit", ref.offset);
    }

    Resource resource(&file, ref, &limits);
    resource.uncompressed_ = ref.uncompressed;
    bool solid = (ref.flags & resFlagSolid) != 0;
    bool compressed = (ref.flags & resFlagCompressed) != 0;
    if (solid && context.version != versionSolid) {
        return fail(ErrorKind::Malformed, "WIM solid resource in a plain WIM", ref.offset);
    }
    if (solid && compressed) {
        return fail(
            ErrorKind::Malformed,
            "WIM resource cannot be solid and compressed",
            ref.offset
        );
    }
    if (!solid && !compressed) {
        if (ref.sizeInWim != ref.uncompressed) {
            return fail(ErrorKind::Malformed, "WIM stored resource size mismatch", ref.offset);
        }
        return resource;
    }
    resource.solid_ = solid;
    resource.compressed_ = compressed;
    auto parsed = resource.parseChunks(context, capBytes);
    if (!parsed) {
        return tl::unexpected<Error>(parsed.error());
    }
    return resource;
}

Result<void> Resource::parseChunks(const ResourceContext& context, std::uint64_t capBytes) {
    if (solid_) {
        if (ref_.sizeInWim < altTableHeaderSize) {
            return fail(ErrorKind::Truncated, "WIM ends inside a solid header", ref_.offset);
        }
        std::array<std::byte, altTableHeaderSize> header{};
        auto read = file_->readExactAt(ref_.offset, header);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        std::uint64_t usize = loadLe<std::uint64_t>(header.data());
        std::uint32_t chunk = loadLe<std::uint32_t>(header.data() + 8);
        std::uint32_t formatValue = loadLe<std::uint32_t>(header.data() + 12);
        if (usize == 0) {
            return fail(ErrorKind::Malformed, "WIM solid resource is empty", ref_.offset);
        }
        if (usize > capBytes) {
            return fail(ErrorKind::LimitExceeded, "WIM resource exceeds size limit", ref_.offset);
        }
        if (!isPowerOfTwo(chunk) || chunk > (std::uint64_t{1} << 31)) {
            return fail(ErrorKind::Malformed, "WIM solid chunk size is invalid", ref_.offset);
        }
        auto format = formatFromValue(formatValue, ref_.offset + 12);
        if (!format) {
            return tl::unexpected<Error>(format.error());
        }
        format_ = *format;
        uncompressed_ = usize;
        chunkSize_ = chunk;
    } else {
        if (context.chunkSize == 0) {
            return fail(ErrorKind::Malformed, "WIM compressed resource has no chunk size");
        }
        format_ = context.compression;
        chunkSize_ = context.chunkSize;
    }

    auto chunks = (uncompressed_ + chunkSize_ - 1) / chunkSize_;
    if (chunks == 0) {
        return fail(ErrorKind::Malformed, "WIM resource holds no chunks", ref_.offset);
    }
    std::uint64_t entries = solid_ ? chunks : chunks - 1;
    tableEntrySize_ = (!solid_ && uncompressed_ > 0xFFFFFFFFULL) ? 8 : 4;
    auto table = checkedMul(entries, static_cast<std::uint64_t>(tableEntrySize_));
    if (!table) {
        return fail(ErrorKind::Malformed, "WIM chunk table overflows", ref_.offset);
    }
    std::uint64_t base = solid_ ? altTableHeaderSize : 0;
    auto tableEnd = checkedAdd(base, *table);
    if (!tableEnd || *tableEnd > ref_.sizeInWim) {
        return fail(ErrorKind::Truncated, "WIM ends inside a chunk table", ref_.offset);
    }
    if (solid_ && *table > limits_->maxChunkTableBytes) {
        return fail(ErrorKind::LimitExceeded, "WIM solid table exceeds limit", ref_.offset);
    }
    chunkCount_ = chunks;
    tableBase_ = ref_.offset + base;
    tableBytes_ = *table;

    auto first = chunkStoredSize(0);
    if (!first) {
        return tl::unexpected<Error>(first.error());
    }
    return {};
}

Result<std::uint64_t> Resource::chunkFileOffset(std::uint64_t chunk) const {
    if (!solid_) {
        if (chunk == 0) {
            return tableBase_ + tableBytes_;
        }
        auto entry = checkedAdd(tableBase_, (chunk - 1) * tableEntrySize_);
        if (!entry) {
            return fail(ErrorKind::Malformed, "WIM chunk table overflows", ref_.offset);
        }
        if (tableEntrySize_ == 8) {
            std::array<std::byte, 8> raw{};
            auto read = file_->readExactAt(*entry, raw);
            if (!read) {
                return tl::unexpected<Error>(read.error());
            }
            auto body = checkedAdd(tableBase_ + tableBytes_, loadLe<std::uint64_t>(raw.data()));
            if (!body) {
                return fail(ErrorKind::Malformed, "WIM chunk offset overflows", *entry);
            }
            return *body;
        }
        std::array<std::byte, 4> raw{};
        auto read = file_->readExactAt(*entry, raw);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        auto body = checkedAdd(
            tableBase_ + tableBytes_,
            static_cast<std::uint64_t>(loadLe<std::uint32_t>(raw.data()))
        );
        if (!body) {
            return fail(ErrorKind::Malformed, "WIM chunk offset overflows", *entry);
        }
        return *body;
    }
    auto sizes = checkedMul(chunk, std::uint64_t{4});
    if (!sizes) {
        return fail(ErrorKind::Malformed, "WIM solid table overflows", ref_.offset);
    }
    std::uint64_t position = 0;
    std::uint64_t at = tableBase_;
    std::uint64_t left = chunk;
    std::array<std::byte, 4096> page{};
    while (left > 0) {
        auto want = static_cast<std::size_t>(left < page.size() / 4 ? left * 4 : page.size());
        want -= want % 4;
        auto got = file_->readExactAt(at, std::span(page).first(want));
        if (!got) {
            return tl::unexpected<Error>(got.error());
        }
        for (std::size_t index = 0; index < want; index += 4) {
            auto size = loadLe<std::uint32_t>(page.data() + index);
            auto next = checkedAdd(position, static_cast<std::uint64_t>(size));
            if (!next) {
                return fail(ErrorKind::Malformed, "WIM solid offsets overflow", at + index);
            }
            position = *next;
        }
        at += want;
        left -= want / 4;
    }
    auto body = checkedAdd(tableBase_ + tableBytes_, position);
    if (!body) {
        return fail(ErrorKind::Malformed, "WIM solid offset overflows", ref_.offset);
    }
    return *body;
}

Result<std::uint64_t> Resource::chunkStoredSize(std::uint64_t chunk) const {
    auto start = chunkFileOffset(chunk);
    if (!start) {
        return tl::unexpected<Error>(start.error());
    }
    std::uint64_t bound = 0;
    if (!solid_ && chunk + 1 < chunkCount_) {
        auto next = chunkFileOffset(chunk + 1);
        if (!next) {
            return tl::unexpected<Error>(next.error());
        }
        if (*next < *start) {
            return fail(ErrorKind::Malformed, "WIM chunk table is not ordered", ref_.offset);
        }
        bound = *next;
    } else {
        auto end = checkedAdd(ref_.offset, ref_.sizeInWim);
        if (!end) {
            return fail(ErrorKind::Malformed, "WIM resource overflows", ref_.offset);
        }
        bound = *end;
    }
    if (bound < *start) {
        return fail(ErrorKind::Malformed, "WIM chunk is out of range", ref_.offset);
    }
    std::uint64_t full = chunkSize_;
    if (chunk + 1 == chunkCount_) {
        full = uncompressed_ - chunk * chunkSize_;
    }
    std::uint64_t stored = bound - *start;
    if (stored == 0 || stored > full) {
        return fail(ErrorKind::Malformed, "WIM chunk size is invalid", *start);
    }
    return stored;
}

Result<void> Resource::refuseChunk(std::uint64_t chunk) const {
    auto start = chunkFileOffset(chunk);
    if (!start) {
        return tl::unexpected<Error>(start.error());
    }
    return refuseFormat(format_, *start);
}

}
