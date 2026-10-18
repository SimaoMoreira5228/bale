#pragma once

#include "archive/chunk.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "io/file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
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

inline archive::WriterOptions fixedOptions(std::uint32_t chunkSize = archive::defaultChunkSize) {
    archive::WriterOptions options;
    options.chunkSize = chunkSize;
    std::array<std::byte, 16> id{};
    for (std::size_t index = 0; index < id.size(); ++index) {
        id[index] = static_cast<std::byte>(0x10 + index);
    }
    options.archiveId = id;
    options.creationTimeNanoseconds = 1700000000000000000;
    return options;
}

inline archive::Writer newWriter(
    const std::filesystem::path& path,
    const archive::WriterOptions& options = fixedOptions()
) {
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = archive::Writer::create(std::move(*file), options);
    REQUIRE(writer);
    return std::move(*writer);
}

inline std::string contents(archive::Reader& reader, const archive::ManifestEntry& entry) {
    std::string out;
    auto streamed = reader.streamFile(entry, [&out](std::span<const std::byte> chunk) {
        out.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    REQUIRE(streamed);
    return out;
}

}
