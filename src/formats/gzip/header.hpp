#pragma once

#include "base/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace bale::gzip {

inline constexpr std::size_t fixedHeaderSize = 10;
inline constexpr std::size_t trailerSize = 8;

inline constexpr std::uint8_t flagText = 0x01;
inline constexpr std::uint8_t flagHeaderCrc = 0x02;
inline constexpr std::uint8_t flagExtra = 0x04;
inline constexpr std::uint8_t flagName = 0x08;
inline constexpr std::uint8_t flagComment = 0x10;

struct Limits {
    std::uint64_t maxOutputBytes = std::uint64_t{1} << 40;
    std::size_t maxExtraBytes = 0xFFFF;
    std::size_t maxNameLength = 4096;
    std::size_t maxCommentLength = 4096;
    std::size_t chunkBytes = std::size_t{64} << 10;
};

struct Header {
    std::string_view name;
    std::string_view comment;
    std::span<const std::byte> extra;
    std::size_t size = 0;
    std::uint32_t mtime = 0;
    std::uint8_t flags = 0;
    std::uint8_t extraFlags = 0;
    std::uint8_t os = 0;

    [[nodiscard]] bool text() const {
        return (flags & flagText) != 0;
    }
};

[[nodiscard]] Result<Header>
parseHeader(std::span<const std::byte> data, const Limits& limits, std::uint64_t offset = 0);

[[nodiscard]] Result<std::size_t> maxHeaderSize(const Limits& limits);

[[nodiscard]] bool looksLikeGzip(std::span<const std::byte> head);

[[nodiscard]] std::array<std::byte, fixedHeaderSize> encodeHeader(int compressionLevel);

[[nodiscard]] std::array<std::byte, trailerSize>
encodeTrailer(std::uint32_t crc, std::uint64_t size);

}
