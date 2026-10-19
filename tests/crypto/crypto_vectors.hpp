#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::test {

inline std::vector<std::byte> hexDecode(std::string_view hex) {
    std::vector<std::byte> out;
    out.reserve(hex.size() / 2);

    auto nibble = [](char digit) -> std::uint8_t {
        if (digit >= '0' && digit <= '9') {
            return static_cast<std::uint8_t>(digit - '0');
        }
        if (digit >= 'a' && digit <= 'f') {
            return static_cast<std::uint8_t>(digit - 'a' + 10);
        }
        return static_cast<std::uint8_t>(digit - 'A' + 10);
    };

    for (std::size_t at = 0; at + 1 < hex.size(); at += 2) {
        auto byte = static_cast<std::uint8_t>((nibble(hex[at]) << 4) | nibble(hex[at + 1]));
        out.push_back(static_cast<std::byte>(byte));
    }
    return out;
}

inline std::string hexEncode(std::span<const std::byte> bytes) {
    constexpr std::string_view digits = "0123456789abcdef";

    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::byte value : bytes) {
        auto byte = static_cast<unsigned>(value);
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0xF]);
    }
    return out;
}

}
