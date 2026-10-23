#pragma once

#include "base/checked.hpp"
#include "base/error.hpp"
#include "formats/wim/header.hpp"
#include "formats/wim/lzx.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace bale::wim {

struct ResourceContext {
    std::uint32_t version = versionDefault;
    Compression compression = Compression::None;
    std::uint32_t chunkSize = 0;
    std::uint64_t fileSize = 0;
};

class Resource {
  public:
    [[nodiscard]] static Result<Resource> open(
        const File& file,
        const ResourceRef& ref,
        const ResourceContext& context,
        const Limits& limits,
        std::uint64_t capBytes
    );

    [[nodiscard]] std::uint64_t uncompressedSize() const {
        return uncompressed_;
    }

    // NOTE: resources borrow their file handle from the owning reader, so a
    // moved reader rebinds every resource to its new address.
    void rebind(const File* file) {
        file_ = file;
    }

    [[nodiscard]] bool isEmpty() const {
        return uncompressed_ == 0;
    }

    template <ChunkSink Sink>
    [[nodiscard]] Result<void> streamRange(
        std::uint64_t offset,
        std::uint64_t size,
        std::span<std::byte> scratch,
        Sink&& sink
    ) const {
        if (size == 0) {
            return {};
        }
        if (scratch.empty()) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty", ref_.offset);
        }
        auto end = checkedAdd(offset, size);
        if (!end || *end > uncompressed_) {
            return fail(ErrorKind::Malformed, "WIM resource range extends past its end");
        }
        if (solid_ || compressed_) {
            return streamChunked(offset, *end, scratch, sink);
        }
        return streamRaw(ref_.offset + offset, size, scratch, sink);
    }

  private:
    Resource(const File* file, ResourceRef ref, const Limits* limits) :
        file_(file), ref_(ref), limits_(limits) {
    }

    [[nodiscard]] Result<void> parseChunks(const ResourceContext& context, std::uint64_t capBytes);

    template <ChunkSink Sink>
    [[nodiscard]] Result<void> streamRaw(
        std::uint64_t at,
        std::uint64_t size,
        std::span<std::byte> scratch,
        Sink&& sink
    ) const {
        while (size > 0) {
            auto want = static_cast<std::size_t>(size < scratch.size() ? size : scratch.size());
            auto chunk = scratch.first(want);
            auto count = file_->readAt(at, chunk);
            if (!count) {
                return std::unexpected(count.error());
            }
            if (*count == 0) {
                return fail(ErrorKind::Truncated, "WIM ends inside a resource", at);
            }
            auto sunk = sink(std::span<const std::byte>(chunk.data(), *count));
            if (!sunk) {
                return std::unexpected(sunk.error());
            }
            at += *count;
            size -= *count;
        }
        return {};
    }

    template <ChunkSink Sink>
    [[nodiscard]] Result<void> streamChunked(
        std::uint64_t begin,
        std::uint64_t end,
        std::span<std::byte> scratch,
        Sink&& sink
    ) const {
        std::uint64_t first = begin / chunkSize_;
        std::uint64_t last = (end - 1) / chunkSize_;
        for (std::uint64_t chunk = first; chunk <= last; ++chunk) {
            std::uint64_t usize = chunkSize_;
            if (chunk + 1 == chunkCount_) {
                usize = uncompressed_ - chunk * chunkSize_;
            }
            auto stored = chunkStoredSize(chunk);
            if (!stored) {
                return std::unexpected(stored.error());
            }
            if (*stored != usize) {
                auto decoded = streamCompressedChunk(chunk, begin, end, sink, *stored, usize);
                if (!decoded) {
                    return std::unexpected(decoded.error());
                }
                if (chunk == last) {
                    break;
                }
                continue;
            }
            auto start = chunkFileOffset(chunk);
            if (!start) {
                return std::unexpected(start.error());
            }
            std::uint64_t chunkBegin = chunk * chunkSize_;
            std::uint64_t from = begin > chunkBegin ? begin - chunkBegin : 0;
            std::uint64_t until = (end - chunkBegin) < usize ? end - chunkBegin : usize;
            auto read = streamRaw(*start + from, until - from, scratch, sink);
            if (!read) {
                return std::unexpected(read.error());
            }
            if (chunk == last) {
                break;
            }
        }
        return {};
    }

    template <ChunkSink Sink>
    [[nodiscard]] Result<void> streamCompressedChunk(
        std::uint64_t chunk,
        std::uint64_t begin,
        std::uint64_t end,
        Sink&& sink,
        std::uint64_t stored,
        std::uint64_t usize
    ) const {
        if (format_ != Compression::Lzx) {
            return refuseChunk(chunk);
        }
        auto start = chunkFileOffset(chunk);
        if (!start) {
            return std::unexpected(start.error());
        }
        auto plain = decodeLzxChunk(*file_, *start, stored, usize, chunkSize_, *start);
        if (!plain) {
            return std::unexpected(plain.error());
        }
        auto base = checkedMul(chunk, chunkSize_);
        if (!base) {
            return fail(ErrorKind::Malformed, "WIM chunk offset overflows", ref_.offset);
        }
        // NOTE: same clamp as the stored path above: the range can span
        // chunks, so slice this chunk's share out of the decoded buffer.
        // The loop bounds guarantee the slice is non-empty here.
        std::uint64_t from = begin > *base ? begin - *base : 0;
        std::uint64_t until = (end - *base) < plain->size() ? end - *base : plain->size();
        if (until <= from || until > plain->size()) {
            return fail(ErrorKind::Malformed, "WIM resource range extends past its end");
        }
        std::span<const std::byte> part(plain->data() + from, until - from);
        return sink(part);
    }

    [[nodiscard]] Result<std::uint64_t> chunkFileOffset(std::uint64_t chunk) const;
    [[nodiscard]] Result<std::uint64_t> chunkStoredSize(std::uint64_t chunk) const;
    [[nodiscard]] Result<void> refuseChunk(std::uint64_t chunk) const;

    const File* file_ = nullptr;
    ResourceRef ref_{};
    const Limits* limits_ = nullptr;
    std::uint64_t uncompressed_ = 0;
    std::uint64_t chunkSize_ = 0;
    std::uint64_t chunkCount_ = 0;
    std::uint64_t tableBase_ = 0;
    std::uint64_t tableBytes_ = 0;
    unsigned tableEntrySize_ = 0;
    Compression format_ = Compression::None;
    bool compressed_ = false;
    bool solid_ = false;
};

}
