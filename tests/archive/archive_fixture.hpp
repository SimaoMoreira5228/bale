#pragma once

#include "archive/chunk.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

namespace bale::test {

inline std::vector<std::byte> fromHex(std::string_view hex) {
    std::vector<std::byte> out;
    auto nibble = [](char digit) {
        return digit <= '9' ? digit - '0' : digit - 'A' + 10;
    };
    for (std::size_t index = 0; index + 1 < hex.size(); index += 3) {
        out.push_back(static_cast<std::byte>(nibble(hex[index]) * 16 + nibble(hex[index + 1])));
    }
    return out;
}

inline std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

inline archive::ChunkKey syntheticKey(std::uint64_t length, std::uint8_t first = 0) {
    archive::ChunkKey key;
    for (std::size_t index = 0; index < key.digest.size(); ++index) {
        key.digest[index] = static_cast<std::byte>(first + index);
    }
    key.length = length;
    return key;
}

inline std::vector<std::byte> readAll(const std::filesystem::path& path) {
    std::vector<std::byte> out;
    auto file = File::openRead(path);
    if (!file) {
        return out;
    }
    auto size = file->size();
    if (!size) {
        return out;
    }
    out.resize(static_cast<std::size_t>(*size));
    if (!file->readExactAt(0, out)) {
        out.clear();
    }
    return out;
}

}
