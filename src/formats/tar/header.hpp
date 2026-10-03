#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace bale::tar {

inline constexpr std::size_t blockSize = 512;

using Block = std::span<const std::byte, blockSize>;

enum class Format : std::uint8_t {
    V7,
    Ustar,
    Gnu,
};

enum class EntryKind : std::uint8_t {
    Regular,
    HardLink,
    Symlink,
    CharDevice,
    BlockDevice,
    Directory,
    Fifo,
    Other,
};

struct Limits {
    std::uint64_t maxExtendedHeaderBytes = std::uint64_t{1} << 20;
    std::size_t maxPathBytes = std::size_t{64} * 1024;
    std::uint64_t maxEntries = 10'000'000;
};

// NOTE: the string views point into the parsed block and are only valid while it is.
struct Header {
    std::string_view name;
    std::string_view prefix;
    std::string_view linkName;
    std::string_view uname;
    std::string_view gname;
    std::uint64_t size = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::int64_t mtime = 0;
    std::uint32_t mode = 0;
    std::uint32_t devMajor = 0;
    std::uint32_t devMinor = 0;
    char typeflag = '0';
    Format format = Format::V7;
};

struct PaxValues {
    std::string path;
    std::string linkPath;
    std::string uname;
    std::string gname;
    std::uint64_t size = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mtimeNanoseconds = 0;
    bool hasPath = false;
    bool hasLinkPath = false;
    bool hasUname = false;
    bool hasGname = false;
    bool hasSize = false;
    bool hasUid = false;
    bool hasGid = false;
    bool hasMtime = false;

    void clear();
    [[nodiscard]] bool empty() const;
};

[[nodiscard]] bool isZeroBlock(Block block);

[[nodiscard]] bool looksLikeTar(Block firstBlock);

[[nodiscard]] Result<std::uint64_t>
parseNumber(std::span<const std::byte> field, std::uint64_t offset);

[[nodiscard]] Result<Header> parseHeader(Block block, std::uint64_t offset);

[[nodiscard]] EntryKind entryKind(char typeflag);

[[nodiscard]] bool entryHasData(EntryKind kind);

[[nodiscard]] std::optional<std::uint64_t> paddedSize(std::uint64_t size);

// NOTE: records are applied in order onto `values`; an empty value removes that key from it.
[[nodiscard]] Result<void> parsePaxRecords(
    std::string_view data,
    std::uint64_t offset,
    const Limits& limits,
    PaxValues& values
);

}
