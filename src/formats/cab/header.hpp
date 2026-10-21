#pragma once

#include "base/error.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace bale::cab {

inline constexpr std::array<std::byte, 4> signature{
    std::byte{'M'},
    std::byte{'S'},
    std::byte{'C'},
    std::byte{'F'},
};

inline constexpr std::size_t headerBaseSize = 36;

inline constexpr std::uint16_t flagPrevCabinet = 0x0001;
inline constexpr std::uint16_t flagNextCabinet = 0x0002;
inline constexpr std::uint16_t flagReservePresent = 0x0004;

inline constexpr std::uint16_t methodStored = 0;
inline constexpr std::uint16_t methodMszip = 1;
inline constexpr std::uint16_t methodQuantum = 2;
inline constexpr std::uint16_t methodLzx = 3;

inline constexpr std::uint16_t folderContinuedFromPrev = 0xFFFD;
inline constexpr std::uint16_t folderContinuedToNext = 0xFFFE;
inline constexpr std::uint16_t folderContinuedBoth = 0xFFFF;

inline constexpr std::uint16_t attribReadOnly = 0x01;
inline constexpr std::uint16_t attribHidden = 0x02;
inline constexpr std::uint16_t attribSystem = 0x04;
inline constexpr std::uint16_t attribDirectory = 0x10;
inline constexpr std::uint16_t attribArchive = 0x20;

struct Limits {
    std::uint64_t maxEntries = 1'000'000;
    std::uint64_t maxEntryBytes = std::uint64_t{1} << 38;
    std::uint64_t maxTotalBytes = std::uint64_t{1} << 40;
    std::uint64_t maxFolderBytes = std::uint64_t{1} << 40;
    std::uint64_t maxReserveBytes = std::uint64_t{1} << 20;
    std::size_t maxNameBytes = 4096;
};

struct DataBlock {
    std::uint64_t payloadOffset = 0;
    std::uint32_t checksum = 0;
    std::uint64_t compressedBytes = 0;
    std::uint64_t uncompressedBytes = 0;
};

struct Folder {
    std::uint64_t dataOffset = 0;
    std::uint64_t uncompressedBytes = 0;
    std::uint16_t method = 0;
    unsigned windowBits = 0;
    std::vector<DataBlock> blocks;
};

struct FileMeta {
    std::string_view name;
    std::uint64_t size = 0;
    std::uint64_t folderOffset = 0;
    std::uint32_t folder = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mode = 0;
    bool directory = false;
    bool spanned = false;
};

struct Model {
    std::uint64_t imageBytes = 0;
    bool hasPrev = false;
    bool hasNext = false;
    std::vector<Folder> folders;
    std::vector<FileMeta> files;
    std::vector<std::string> names;
};

[[nodiscard]] bool looksLikeCab(std::span<const std::byte> head);

[[nodiscard]] Result<Model>
parseCabinet(const File& file, std::uint64_t fileSize, const Limits& limits);

[[nodiscard]] std::int64_t dosToUnix(std::uint16_t date, std::uint16_t time);

}
