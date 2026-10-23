#pragma once

#include "base/error.hpp"
#include "formats/cpio/header.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::cpio {

struct Entry {
    std::string_view name;
    std::string_view linkTarget;
    std::uint64_t dataOffset = 0;
    std::uint64_t size = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::uint32_t mode = 0;
    std::uint32_t devMajor = 0;
    std::uint32_t devMinor = 0;
    std::uint32_t check = 0;
    bool checksum = false;
    EntryKind kind = EntryKind::Regular;
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
        if (entry.size == 0 || entry.kind == EntryKind::HardLink) {
            return {};
        }
        if (entry.kind != EntryKind::Regular && entry.kind != EntryKind::Symlink) {
            return {};
        }
        if (scratch.empty()) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty", entry.dataOffset);
        }

        std::uint32_t running = 0;
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
                return fail(ErrorKind::Truncated, "cpio archive ends inside entry data", position);
            }

            auto view = std::span<const std::byte>(chunk.data(), *count);
            for (std::byte byte : view) {
                running += static_cast<std::uint8_t>(byte);
            }

            auto sunk = sink(view);
            if (!sunk) {
                return tl::unexpected<Error>(sunk.error());
            }

            position += *count;
            left -= *count;
        }

        if (entry.kind == EntryKind::Regular && entry.checksum && running != entry.check) {
            return fail(ErrorKind::Integrity, "cpio checksum mismatch", entry.dataOffset);
        }
        return {};
    }

  private:
    struct Identity {
        std::uint32_t fsMajor = 0;
        std::uint32_t fsMinor = 0;
        std::uint64_t ino = 0;

        friend bool operator==(const Identity&, const Identity&) = default;
    };

    struct IdentityHash {
        [[nodiscard]] std::size_t operator()(const Identity& identity) const noexcept {
            auto mixed = std::hash<std::uint64_t>{}(identity.ino);
            mixed ^= std::hash<std::uint32_t>{}(identity.fsMajor) + 0x9E3779B9 + (mixed << 6) +
                (mixed >> 2);
            mixed ^= std::hash<std::uint32_t>{}(identity.fsMinor) + 0x9E3779B9 + (mixed << 6) +
                (mixed >> 2);
            return mixed;
        }
    };

    struct Pending {
        std::size_t index = 0;
        Identity identity;
        std::uint64_t nlink = 0;
    };

    explicit Reader(File file, const Limits& limits) : file_(std::move(file)), limits_(limits) {
    }

    [[nodiscard]] Result<void> index(std::uint64_t fileSize);
    [[nodiscard]] Result<bool> indexOne(std::uint64_t& offset, std::uint64_t fileSize);
    void resolveHardLinks();

    File file_;
    Limits limits_;
    std::uint64_t totalBytes_ = 0;
    std::vector<std::string> names_;
    std::vector<Entry> entries_;
    std::vector<Pending> pending_;
};

}
