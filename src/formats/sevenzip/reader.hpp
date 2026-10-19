#pragma once

#include "base/error.hpp"
#include "formats/sevenzip/folder.hpp"
#include "formats/sevenzip/header.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::sevenzip {

struct Entry {
    std::string_view name;
    std::uint64_t size = 0;
    std::optional<std::uint64_t> folder;
    std::uint64_t offset = 0;
    std::optional<std::uint32_t> crc;
    std::optional<std::int64_t> mtimeNanoseconds;
    std::optional<std::uint32_t> mode;
    bool directory = false;
};

class Reader {
  public:
    [[nodiscard]] static Result<Reader> open(File file, const Limits& limits = {});

    [[nodiscard]] std::uint64_t entryCount() const {
        return entries_.size();
    }

    [[nodiscard]] std::uint64_t folderCount() const {
        return plans_.size();
    }

    [[nodiscard]] std::span<const Entry> entries() const {
        return entries_;
    }

    template <ChunkSink Sink>
    [[nodiscard]] Result<void>
    streamEntry(const Entry& entry, std::span<std::byte> scratch, Sink&& sink) {
        if (!entry.folder) {
            if (entry.size != 0) {
                return fail(ErrorKind::Malformed, "7z entry has no data");
            }
            return {};
        }

        auto session = sessionFor(entry);
        if (!session) {
            return std::unexpected(session.error());
        }

        auto started = (*session)->startEntry(entry.offset, entry.size, entry.crc, scratch);
        if (!started) {
            active_.reset();
            return std::unexpected(started.error());
        }

        while (true) {
            auto chunk = (*session)->nextChunk();
            if (!chunk) {
                active_.reset();
                return std::unexpected(chunk.error());
            }
            if (chunk->empty()) {
                return {};
            }

            auto sunk = sink(*chunk);
            if (!sunk) {
                active_.reset();
                return std::unexpected(sunk.error());
            }
        }
    }

  private:
    struct Active {
        std::uint64_t folder = 0;
        FolderSession session;
    };

    explicit Reader(File file, const Limits& limits) : file_(std::move(file)), limits_(limits) {
    }

    [[nodiscard]] Result<FolderSession*> sessionFor(const Entry& entry);

    File file_;
    Limits limits_;
    std::vector<std::string> names_;
    std::vector<Entry> entries_;
    std::vector<Result<FolderPlan>> plans_;
    std::optional<Active> active_;
    std::optional<Inflater> inflater_;
    std::optional<Bzip2Decoder> bzip2_;
};

[[nodiscard]] bool looksLikeSevenZip(std::span<const std::byte> head);

}
