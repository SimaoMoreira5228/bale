#include "formats/wim/lzx.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "formats/cab/lzx.hpp"

#include <array>

namespace bale::wim {

namespace {

inline constexpr std::uint64_t maxLzxWindowBytes = std::uint64_t{1} << 21;
inline constexpr std::uint64_t minLzxWindowBytes = std::uint64_t{1} << 15;
inline constexpr std::size_t feedSliceBytes = 65536;

[[nodiscard]] bool isPowerOfTwo(std::uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

}

Result<unsigned> windowBitsForChunk(std::uint64_t chunkSize, std::uint64_t at) {
    if (!isPowerOfTwo(chunkSize)) {
        return fail(ErrorKind::Malformed, "WIM LZX chunk size is not a power of two", at);
    }
    if (chunkSize < minLzxWindowBytes || chunkSize > maxLzxWindowBytes) {
        return fail(ErrorKind::Unsupported, "WIM LZX chunk size is not supported", at);
    }
    unsigned bits = 0;
    std::uint64_t size = chunkSize;
    while (size > 1) {
        size >>= 1;
        ++bits;
    }
    return bits;
}

void undoE8Chunk(std::span<std::byte> chunk) {
    if (chunk.size() <= lzxE8TailBytes) {
        return;
    }
    std::size_t bound = chunk.size() - lzxE8TailBytes;
    auto fileSize = static_cast<std::int64_t>(lzxE8FileSize);
    std::size_t index = 0;
    while (index < bound) {
        if (chunk[index] != std::byte{0xE8}) {
            ++index;
            continue;
        }
        std::int32_t value =
            static_cast<std::int32_t>(loadLe<std::uint32_t>(chunk.data() + index + 1));
        auto current = static_cast<std::int64_t>(index);
        if (static_cast<std::int64_t>(value) >= -current &&
            static_cast<std::int64_t>(value) < fileSize) {
            std::int64_t target = value >= 0 ? static_cast<std::int64_t>(value) - current
                                             : static_cast<std::int64_t>(value) + fileSize;
            storeLe(chunk.data() + index + 1, static_cast<std::uint32_t>(target));
        }
        index += 5;
    }
}

Result<std::vector<std::byte>> decodeLzxChunk(
    const File& file,
    std::uint64_t storedAt,
    std::uint64_t storedSize,
    std::uint64_t uncompressedSize,
    std::uint64_t chunkSize,
    std::uint64_t at
) {
    if (uncompressedSize == 0 || uncompressedSize > chunkSize) {
        return fail(ErrorKind::Malformed, "WIM LZX chunk size is invalid", at);
    }
    if (storedSize == 0 || storedSize >= uncompressedSize) {
        return fail(ErrorKind::Malformed, "WIM LZX chunk size is invalid", at);
    }
    auto fileSize = file.size();
    if (!fileSize) {
        return tl::unexpected<Error>(fileSize.error());
    }
    if (!fitsWithin(storedAt, storedSize, *fileSize)) {
        return fail(ErrorKind::Truncated, "WIM ends inside an LZX chunk", at);
    }
    auto bits = windowBitsForChunk(chunkSize, at);
    if (!bits) {
        return tl::unexpected<Error>(bits.error());
    }
    auto decoder = cab::LzxDecoder::create(*bits, uncompressedSize, cab::LzxFraming::Wim);
    if (!decoder) {
        return tl::unexpected<Error>(decoder.error());
    }
    auto total = checkedCast<std::size_t>(uncompressedSize);
    if (!total) {
        return fail(ErrorKind::LimitExceeded, "WIM LZX chunk exceeds size limit", at);
    }
    std::vector<std::byte> out(*total);
    std::size_t produced = 0;
    std::uint64_t fed = 0;
    std::array<std::byte, feedSliceBytes> slice{};
    bool needInput = true;
    while (produced < out.size()) {
        if (needInput && fed < storedSize) {
            std::uint64_t left = storedSize - fed;
            std::size_t take = left < slice.size() ? static_cast<std::size_t>(left) : slice.size();
            auto here = checkedAdd(storedAt, fed);
            if (!here) {
                return fail(ErrorKind::Malformed, "WIM LZX chunk offset overflows", at);
            }
            auto read = file.readExactAt(*here, std::span(slice).first(take));
            if (!read) {
                return tl::unexpected<Error>(read.error());
            }
            auto pushed = decoder->push(std::span<const std::byte>(slice.data(), take));
            if (!pushed) {
                return tl::unexpected<Error>(pushed.error());
            }
            fed += take;
            needInput = false;
        }
        auto window = std::span(out).subspan(produced);
        auto stepped = decoder->decode(window);
        if (!stepped) {
            auto error = stepped.error();
            if (error.offset == Error::noOffset) {
                error.offset = at;
            }
            return tl::unexpected<Error>(error);
        }
        produced += stepped->produced;
        if (stepped->produced == 0) {
            if (!stepped->starved) {
                break;
            }
            if (fed >= storedSize) {
                return fail(ErrorKind::Malformed, "WIM LZX chunk ends early", at);
            }
            needInput = true;
        }
    }
    auto tail = decoder->finish();
    if (!tail) {
        auto error = tail.error();
        if (error.offset == Error::noOffset) {
            error.offset = at;
        }
        return tl::unexpected<Error>(error);
    }
    if (!tail->empty()) {
        return fail(ErrorKind::Malformed, "WIM LZX chunk exceeds its declared size", at);
    }
    if (produced != out.size()) {
        return fail(ErrorKind::Malformed, "WIM LZX chunk ends early", at);
    }
    undoE8Chunk(out);
    return out;
}

}
