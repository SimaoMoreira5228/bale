#pragma once

#include "base/endian.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace bale::sevenzip::test {

using Bytes = std::vector<std::byte>;

inline void put8(Bytes& out, std::uint8_t value) {
    out.push_back(static_cast<std::byte>(value));
}

inline void put16(Bytes& out, std::uint16_t value) {
    std::array<std::byte, 2> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

inline void put32(Bytes& out, std::uint32_t value) {
    std::array<std::byte, 4> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

inline void put64(Bytes& out, std::uint64_t value) {
    std::array<std::byte, 8> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

inline void putNumber(Bytes& out, std::uint64_t value) {
    if (value < 0x80) {
        put8(out, static_cast<std::uint8_t>(value));
        return;
    }

    std::uint8_t extra = 0;
    std::uint64_t shifted = value;
    while (shifted >= (std::uint64_t{1} << (7 + 7 * extra))) {
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

inline void putText(Bytes& out, std::string_view text) {
    for (char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
}

inline void putUtf16(Bytes& out, std::string_view utf8) {
    std::size_t index = 0;
    while (index < utf8.size()) {
        auto byte = static_cast<unsigned char>(utf8[index]);
        char32_t point = 0;
        std::size_t width = 0;
        if (byte < 0x80) {
            point = byte;
            width = 1;
        } else if ((byte & 0xE0) == 0xC0) {
            point = byte & 0x1F;
            width = 2;
        } else if ((byte & 0xF0) == 0xE0) {
            point = byte & 0x0F;
            width = 3;
        } else {
            point = byte & 0x07;
            width = 4;
        }
        for (std::size_t tail = 1; tail < width; ++tail) {
            point = (point << 6) | (static_cast<unsigned char>(utf8[index + tail]) & 0x3F);
        }
        index += width;

        if (point < 0x10000) {
            put16(out, static_cast<std::uint16_t>(point));
        } else {
            point -= 0x10000;
            put16(out, static_cast<std::uint16_t>(0xD800 + (point >> 10)));
            put16(out, static_cast<std::uint16_t>(0xDC00 + (point & 0x3FF)));
        }
    }
    put16(out, 0);
}

inline void patch8(Bytes& out, std::size_t at, std::uint8_t value) {
    out[at] = static_cast<std::byte>(value);
}

inline void patch16(Bytes& out, std::size_t at, std::uint16_t value) {
    storeLe(out.data() + at, value);
}

inline void patch32(Bytes& out, std::size_t at, std::uint32_t value) {
    storeLe(out.data() + at, value);
}

inline void patch64(Bytes& out, std::size_t at, std::uint64_t value) {
    storeLe(out.data() + at, value);
}

inline std::span<const std::byte> asBytes(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

}
