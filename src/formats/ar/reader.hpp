#pragma once

#include "base/error.hpp"
#include "formats/ar/header.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::ar {

struct Entry {
    std::string_view name;
    std::uint64_t dataOffset = 0;
    std::uint64_t size = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::uint32_t mode = 0;
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
        if (entry.size == 0) {
            return {};
        }
        if (scratch.empty()) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty", entry.dataOffset);
        }

        std::uint64_t position = entry.dataOffset;
        std::uint64_t left = entry.size;
        while (left > 0) {
            auto want = static_cast<std::size_t>(left < scratch.size() ? left : scratch.size());
            auto chunk = scratch.first(want);

            auto count = file_.readAt(position, chunk);
            if (!count) {
                return tl::unexpected<Error>(count.error());
            }
            if (*count == 0) {
                return fail(ErrorKind::Truncated, "ar archive ends inside entry data", position);
            }

            auto sunk = sink(std::span<const std::byte>(chunk.data(), *count));
            if (!sunk) {
                return tl::unexpected<Error>(sunk.error());
            }

            position += *count;
            left -= *count;
        }
        return {};
    }

  private:
    explicit Reader(File file, const Limits& limits) : file_(std::move(file)), limits_(limits) {
    }

    [[nodiscard]] Result<void> index(std::uint64_t fileSize);
    [[nodiscard]] Result<void> addMember(const Member& member, std::uint64_t fileSize);
    [[nodiscard]] Result<void> addNamed(
        const Member& member,
        std::string_view name,
        std::uint64_t dataOffset,
        std::uint64_t size,
        std::uint64_t fileSize
    );
    [[nodiscard]] Result<std::string_view> resolveGnuName(const Member& member);
    [[nodiscard]] Result<void> resolveBsdName(
        const Member& member,
        std::string_view& name,
        std::uint64_t& dataOffset,
        std::uint64_t& size
    );

    File file_;
    Limits limits_;
    std::uint64_t totalBytes_ = 0;
    std::vector<std::string> names_;
    std::vector<Entry> entries_;
    std::string stringTable_;
    std::string extendedName_;
    bool hasStringTable_ = false;
};

}
