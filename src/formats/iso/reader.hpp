#pragma once

#include "base/error.hpp"
#include "formats/iso/directory.hpp"
#include "formats/iso/header.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::iso {

struct Entry {
    std::string_view name;
    std::string_view linkTarget;
    std::uint64_t size = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mode = 0;
    EntryKind kind = EntryKind::Regular;
    std::size_t extentBegin = 0;
    std::size_t extentEnd = 0;
};

class Reader {
  public:
    [[nodiscard]] static Result<Reader> open(File file, const Limits& limits = {});

    [[nodiscard]] std::uint64_t entryCount() const {
        return entries_.size();
    }

    [[nodiscard]] std::span<const Entry> entries() const {
        return entries_;
    }

    template <ChunkSink Sink>
    [[nodiscard]] Result<void>
    streamEntry(const Entry& entry, std::span<std::byte> scratch, Sink&& sink) {
        if (entry.kind != EntryKind::Regular || entry.size == 0) {
            return {};
        }
        if (scratch.empty()) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty", entry.extentBegin);
        }

        for (std::size_t index = entry.extentBegin; index < entry.extentEnd; ++index) {
            const Extent& extent = extents_[index];
            std::uint64_t position = extent.offset;
            std::uint64_t left = extent.length;
            while (left > 0) {
                auto want = static_cast<std::size_t>(left < scratch.size() ? left : scratch.size());
                auto chunk = scratch.first(want);

                auto count = file_.readAt(position, chunk);
                if (!count) {
                    return tl::unexpected<Error>(count.error());
                }
                if (*count == 0) {
                    return fail(ErrorKind::Truncated, "ISO image ends inside entry data", position);
                }

                auto sunk = sink(std::span<const std::byte>(chunk.data(), *count));
                if (!sunk) {
                    return tl::unexpected<Error>(sunk.error());
                }

                position += *count;
                left -= *count;
            }
        }
        return {};
    }

  private:
    explicit Reader(File file, const Limits& limits) : file_(std::move(file)), limits_(limits) {
    }

    [[nodiscard]] Result<void> addNodes(std::vector<Node>&& others);

    File file_;
    Limits limits_;
    std::uint64_t totalBytes_ = 0;
    std::vector<std::string> names_;
    std::vector<std::string> targets_;
    std::vector<Extent> extents_;
    std::vector<Entry> entries_;
};

}
