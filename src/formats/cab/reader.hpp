#pragma once

#include "base/error.hpp"
#include "formats/cab/header.hpp"
#include "formats/cab/session.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace bale::cab {

struct Entry {
    std::string_view name;
    std::uint64_t size = 0;
    std::uint32_t folder = 0;
    std::uint64_t folderOffset = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mode = 0;
    bool directory = false;
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
        if (entry.size == 0 || entry.directory) {
            return {};
        }
        if (scratch.empty()) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty", entry.folderOffset);
        }
        if (entry.size > limits_.maxEntryBytes) {
            return fail(ErrorKind::LimitExceeded, "cabinet entry exceeds size limit");
        }

        auto session = sessionFor(entry);
        if (!session) {
            return tl::unexpected<Error>(session.error());
        }

        auto started = (*session)->startEntry(entry.folderOffset, entry.size, scratch);
        if (!started) {
            active_.reset();
            return tl::unexpected<Error>(started.error());
        }

        while (true) {
            auto chunk = (*session)->nextChunk();
            if (!chunk) {
                active_.reset();
                return tl::unexpected<Error>(chunk.error());
            }
            if (chunk->empty()) {
                return {};
            }

            auto sunk = sink(*chunk);
            if (!sunk) {
                active_.reset();
                return tl::unexpected<Error>(sunk.error());
            }
        }
    }

  private:
    struct Active {
        std::uint32_t folder = 0;
        Session session;
    };

    explicit Reader(File file, const Limits& limits) : file_(std::move(file)), limits_(limits) {
    }

    [[nodiscard]] Result<Session*> sessionFor(const Entry& entry);

    File file_;
    Limits limits_;
    Model model_;
    std::vector<Entry> entries_;
    std::optional<Active> active_;
    std::optional<Inflater> inflater_;
};

}
