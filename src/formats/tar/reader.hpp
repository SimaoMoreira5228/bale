#pragma once

#include "base/error.hpp"
#include "formats/tar/header.hpp"
#include "formats/tar/source.hpp"
#include "io/chunk_sink.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
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
    explicit Reader(Source source, const Limits& limits = {}) :
        source_(std::move(source)), limits_(limits) {
    }

    [[nodiscard]] Result<const Entry*> next();

    template <ChunkSink Sink>
    [[nodiscard]] Result<void> streamData(std::span<std::byte> scratch, Sink&& sink) {
        if (failure_) {
            return std::unexpected(*failure_);
        }
        if (scratch.empty() && dataLeft_ != 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }

        while (dataLeft_ > 0) {
            auto chunk = scratch.first(
                static_cast<std::size_t>(std::min<std::uint64_t>(dataLeft_, scratch.size()))
            );
            auto read = readData(chunk);
            if (!read) {
                return read;
            }

            auto sunk = sink(std::span<const std::byte>(chunk));
            if (!sunk) {
                return sunk;
            }
        }
        return {};
    }

  private:
    enum class BlockState : std::uint8_t {
        Header,
        Zero,
        End,
    };

    [[nodiscard]] Result<const Entry*> readNext();
    [[nodiscard]] Result<void> readData(std::span<std::byte> out);
    [[nodiscard]] Result<void> readExact(std::span<std::byte> out);
    [[nodiscard]] Result<BlockState> readBlock();
    [[nodiscard]] Result<std::uint64_t> padding(std::uint64_t dataOffset, std::uint64_t size) const;
    [[nodiscard]] Result<void> readMetaData(const Header& header, std::string& buffer);
    [[nodiscard]] Result<const Entry*> endOfArchive(BlockState state, bool pendingMeta);
    [[nodiscard]] Result<const Entry*> finishEntry(const Header& header);

    Source source_;
    Limits limits_;
    std::uint64_t position_ = 0;
    std::uint64_t dataLeft_ = 0;
    std::uint64_t paddingLeft_ = 0;
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
