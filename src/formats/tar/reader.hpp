#pragma once

#include "base/error.hpp"
#include "formats/tar/header.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace bale::tar {

struct Entry {
    std::string_view path;
    std::string_view linkTarget;
    std::string_view uname;
    std::string_view gname;
    std::uint64_t headerOffset = 0;
    std::uint64_t dataOffset = 0;
    std::uint64_t size = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mtimeNanoseconds = 0;
    std::uint32_t mode = 0;
    std::uint32_t devMajor = 0;
    std::uint32_t devMinor = 0;
    EntryKind kind = EntryKind::Regular;
    Format format = Format::V7;
    char typeflag = '0';
};

class Reader {
  public:
    [[nodiscard]] static Result<Reader> open(File file, const Limits& limits = {});

    // NOTE: returns nullptr at the end of the archive. The entry and its string views stay valid
    // only until the next call to next() or until the reader is moved or destroyed. After an
    // error every later call returns the same error.
    [[nodiscard]] Result<const Entry*> next();

  private:
    enum class BlockState : std::uint8_t {
        Header,
        Zero,
        End,
    };

    Reader(File file, std::uint64_t fileSize, const Limits& limits) :
        file_(std::move(file)), fileSize_(fileSize), limits_(limits) {
    }

    [[nodiscard]] Result<const Entry*> readNext();
    [[nodiscard]] Result<BlockState> readBlock(std::uint64_t offset);
    [[nodiscard]] Result<std::uint64_t> dataEnd(std::uint64_t dataOffset, std::uint64_t size) const;
    [[nodiscard]] Result<void> readMetaData(const Header& header, std::string& buffer);
    [[nodiscard]] Result<const Entry*> endOfArchive(BlockState state, bool pendingMeta);
    [[nodiscard]] Result<const Entry*> finishEntry(const Header& header);

    File file_;
    std::uint64_t fileSize_;
    Limits limits_;
    std::uint64_t position_ = 0;
    std::uint64_t entryCount_ = 0;
    bool done_ = false;
    std::optional<Error> failure_;
    std::array<std::byte, blockSize> block_{};
    std::string metaBuffer_;
    std::string path_;
    std::string longPath_;
    std::string longLink_;
    bool hasLongPath_ = false;
    bool hasLongLink_ = false;
    PaxValues localPax_;
    PaxValues globalPax_;
    Entry entry_;
};

}
