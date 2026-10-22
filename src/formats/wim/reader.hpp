#pragma once

#include "base/error.hpp"
#include "formats/wim/header.hpp"
#include "formats/wim/lookup.hpp"
#include "formats/wim/metadata.hpp"
#include "formats/wim/resource.hpp"
#include "formats/wim/xml.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace bale::wim {

struct Entry {
    std::string_view name;
    std::string_view linkTarget;
    std::uint64_t size = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mode = 0;
    EntryKind kind = EntryKind::Regular;
};

class Reader {
  public:
    [[nodiscard]] static Result<Reader>
    open(File file, const Limits& limits = {}, std::uint32_t imageIndex = 0);

    [[nodiscard]] std::uint64_t entryCount() const {
        return entries_.size();
    }

    [[nodiscard]] std::span<const Entry> entries() const {
        return entries_;
    }

    [[nodiscard]] std::uint32_t selectedImage() const {
        return selected_;
    }

    [[nodiscard]] std::span<const ImageInfo> images() const {
        return images_;
    }

    [[nodiscard]] std::uint32_t bootImage() const {
        return boot_;
    }

    [[nodiscard]] Compression compression() const {
        return compression_;
    }

    Reader(Reader&& other) noexcept;
    Reader& operator=(Reader&& other) noexcept;

    template <ChunkSink Sink>
    [[nodiscard]] Result<void>
    streamEntry(const Entry& entry, std::span<std::byte> scratch, Sink&& sink) {
        if (entry.kind != EntryKind::Regular && entry.kind != EntryKind::AlternateStream) {
            return {};
        }
        if (entry.size == 0) {
            return {};
        }
        if (scratch.empty()) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }
        auto located = locate(entry);
        if (!located) {
            return std::unexpected(located.error());
        }
        const Resource& resource = located->solid ? solidResources_[located->run][located->slot]
                                                  : resources_[located->slot];
        return resource.streamRange(located->base, entry.size, scratch, sink);
    }

  private:
    struct Located {
        std::uint32_t run = 0;
        std::uint32_t slot = 0;
        std::uint64_t base = 0;
        bool solid = false;
        bool valid = false;
    };

    struct BlobKey {
        std::array<std::byte, hashSize> bytes{};

        bool operator==(const BlobKey& other) const {
            return bytes == other.bytes;
        }
    };

    struct BlobKeyHasher {
        std::size_t operator()(const BlobKey& key) const noexcept {
            std::size_t folded = 0;
            for (std::size_t index = 0; index < key.bytes.size(); ++index) {
                folded = folded * 1315423911U + static_cast<unsigned char>(key.bytes[index]);
            }
            return folded;
        }
    };

    explicit Reader(File file, const Limits& limits) : file_(std::move(file)), limits_(limits) {
    }

    [[nodiscard]] Result<Located> locate(const Entry& entry) {
        const Entry* begin = entries_.data();
        const Entry* end = begin + entries_.size();
        if (&entry < begin || &entry >= end) {
            return fail(ErrorKind::Malformed, "WIM entry is not from this reader");
        }
        std::size_t index = static_cast<std::size_t>(&entry - begin);
        if (!locations_[index].valid) {
            return fail(ErrorKind::Malformed, "WIM entry references no data");
        }
        return locations_[index];
    }

    File file_;
    Limits limits_;
    Compression compression_ = Compression::None;
    std::vector<ImageInfo> images_;
    std::uint32_t selected_ = 0;
    std::uint32_t boot_ = 0;
    std::unordered_map<BlobKey, std::size_t, BlobKeyHasher> blobIndex_;
    std::vector<Resource> resources_;
    std::vector<std::vector<Resource>> solidResources_;
    std::vector<std::string> names_;
    std::vector<std::string> targets_;
    std::vector<Entry> entries_;
    std::vector<Located> locations_;
    std::uint64_t totalBytes_ = 0;
};

}
