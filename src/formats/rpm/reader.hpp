#pragma once

#include "base/error.hpp"
#include "formats/cpio/header.hpp"
#include "formats/cpio/reader.hpp"
#include "formats/rpm/header.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace bale::rpm {

using EntryKind = cpio::EntryKind;

struct Entry {
    std::string_view name;
    std::string_view linkTarget;
    std::uint64_t size = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mode = 0;
    EntryKind kind = EntryKind::Regular;
    std::size_t payloadIndex = 0;
};

class Reader {
  public:
    [[nodiscard]] static Result<Reader> open(File file, const Limits& limits = {});

    Reader(Reader&&) noexcept = default;
    Reader& operator=(Reader&&) noexcept = default;

    [[nodiscard]] const Package& package() const {
        return package_;
    }

    [[nodiscard]] std::uint64_t entryCount() const {
        return entries_.size();
    }

    [[nodiscard]] std::span<const Entry> entries() const {
        return entries_;
    }

    template <ChunkSink Sink>
    [[nodiscard]] Result<void>
    streamEntry(const Entry& entry, std::span<std::byte> scratch, Sink&& sink) {
        if (!cpio_) {
            return fail(ErrorKind::Malformed, "rpm entry is not from this reader");
        }
        const auto payload = cpio_->entries();
        if (entry.payloadIndex >= payload.size()) {
            return fail(ErrorKind::Malformed, "rpm entry is not from this reader");
        }
        return cpio_->streamEntry(payload[entry.payloadIndex], scratch, std::forward<Sink>(sink));
    }

  private:
    // NOTE: staged payload files live on disk (not in memory) so arbitrarily
    // large payloads stream within the decompression and cpio budgets; the
    // paths are removed best-effort on destruction.
    struct Staged {
        std::filesystem::path path;
        bool armed = false;

        Staged() = default;
        Staged(const Staged&) = delete;
        Staged& operator=(const Staged&) = delete;
        Staged(Staged&& other) noexcept;
        Staged& operator=(Staged&& other) noexcept;
        ~Staged();

        void release();
    };

    explicit Reader(Package package, const Limits& limits) :
        package_(std::move(package)), limits_(limits) {
    }

    Package package_;
    Limits limits_;
    Staged payload_;
    std::optional<cpio::Reader> cpio_;
    std::vector<Entry> entries_;
};

}
