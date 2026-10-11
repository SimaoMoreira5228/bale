#pragma once

#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "codecs/deflate_encoder.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

#include <zstd.h>

namespace bale::test {

inline constexpr std::string_view goldenDeflateText =
    "bale bale bale: golden deflate vector, golden deflate vector!\n";

// NOTE: produced by CPython zlib.compressobj(9, zlib.DEFLATED, -15) from goldenDeflateText.
inline std::vector<std::byte> goldenDeflate() {
    constexpr std::array<std::uint8_t, 37> raw{
        0x4b, 0x4a, 0xcc, 0x49, 0x55, 0x48, 0x82, 0x11, 0x56, 0x0a, 0xe9, 0xf9, 0x39,
        0x29, 0xa9, 0x79, 0x0a, 0x29, 0xa9, 0x69, 0x39, 0x89, 0x25, 0xa9, 0x0a, 0x65,
        0xa9, 0xc9, 0x25, 0xf9, 0x45, 0x3a, 0xd8, 0x85, 0x15, 0xb9, 0x00,
    };
    std::vector<std::byte> out;
    out.reserve(raw.size());
    for (auto value : raw) {
        out.push_back(std::byte{value});
    }
    return out;
}

inline std::vector<std::byte> deflateRaw(std::span<const std::byte> data) {
    auto encoder = DeflateEncoder::create(9);
    if (!encoder) {
        return {};
    }

    std::vector<std::byte> out(DeflateEncoder::compressBound(data.size()));
    auto size = encoder->compress(data, out);
    out.resize(size ? *size : 0);
    return out;
}

inline std::vector<std::byte> deflateRaw(std::string_view text) {
    return deflateRaw(std::as_bytes(std::span(text.data(), text.size())));
}

// NOTE: one gzip member with an optional FNAME; GNU gzip writes the same layout.
inline std::vector<std::byte>
gzipMember(std::span<const std::byte> data, std::string_view name = {}, std::uint32_t mtime = 0) {
    std::vector<std::byte> out{
        std::byte{0x1f},
        std::byte{0x8b},
        std::byte{8},
        std::byte{name.empty() ? std::uint8_t{0} : std::uint8_t{0x08}},
    };
    std::array<std::byte, 4> word{};
    storeLe(word.data(), mtime);
    out.insert(out.end(), word.begin(), word.end());
    out.push_back(std::byte{0});
    out.push_back(std::byte{3});
    if (!name.empty()) {
        for (char value : name) {
            out.push_back(static_cast<std::byte>(value));
        }
        out.push_back(std::byte{0});
    }

    auto packed = deflateRaw(data);
    out.insert(out.end(), packed.begin(), packed.end());
    storeLe(word.data(), Crc32::of(data));
    out.insert(out.end(), word.begin(), word.end());
    storeLe(word.data(), static_cast<std::uint32_t>(data.size()));
    out.insert(out.end(), word.begin(), word.end());
    return out;
}

// NOTE: the size is never pledged, so the frame header carries the full window instead of a
// window shrunk to the content size.
inline std::vector<std::byte> zstdCompress(std::span<const std::byte> data, int windowLog) {
    ZSTD_CCtx* context = ZSTD_createCCtx();
    ZSTD_CCtx_setParameter(context, ZSTD_c_windowLog, windowLog);
    ZSTD_CCtx_setParameter(context, ZSTD_c_checksumFlag, 1);

    std::vector<std::byte> out(ZSTD_compressBound(data.size()) + 64);
    ZSTD_inBuffer in{.src = data.data(), .size = data.size(), .pos = 0};
    ZSTD_outBuffer sink{.dst = out.data(), .size = out.size(), .pos = 0};
    auto first = ZSTD_compressStream2(context, &sink, &in, ZSTD_e_continue);
    ZSTD_inBuffer none{.src = nullptr, .size = 0, .pos = 0};
    auto last = ZSTD_compressStream2(context, &sink, &none, ZSTD_e_end);
    ZSTD_freeCCtx(context);

    out.resize(ZSTD_isError(first) != 0U || last != 0 ? 0 : sink.pos);
    return out;
}

}
