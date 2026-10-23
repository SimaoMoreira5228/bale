#pragma once

#include "base/error.hpp"
#include "formats/bzip2/stream.hpp"
#include "formats/gzip/stream.hpp"
#include "formats/xz/stream.hpp"
#include "formats/zstd/stream.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

namespace bale {

enum class Compression : std::uint8_t {
    None,
    Gzip,
    Zstd,
    Xz,
    Bzip2,
};

struct DecompressLimits {
    std::uint64_t maxOutputBytes = std::uint64_t{1} << 40;
    std::size_t chunkBytes = std::size_t{64} << 10;
};

class CompressedStream {
  public:
    [[nodiscard]] static Result<CompressedStream>
    open(File file, Compression compression, const DecompressLimits& limits = {});

    [[nodiscard]] Compression compression() const;

    [[nodiscard]] const gzip::Header* gzipHeader() const;

    [[nodiscard]] std::uint64_t outputBytes() const;

    [[nodiscard]] Result<std::size_t> read(std::span<std::byte> out);

    template <ChunkSink Sink>
    [[nodiscard]] Result<void> readAll(std::span<std::byte> scratch, Sink&& sink) {
        while (true) {
            auto count = read(scratch);
            if (!count) {
                return tl::unexpected<Error>(count.error());
            }
            if (*count == 0) {
                return {};
            }

            auto sunk = sink(std::span<const std::byte>(scratch.first(*count)));
            if (!sunk) {
                return sunk;
            }
        }
    }

  private:
    using Codec = std::variant<gzip::Stream, zstd::Stream, xz::Stream, bzip2::Stream>;

    explicit CompressedStream(Codec codec) : codec_(std::move(codec)) {
    }

    Codec codec_;
};

}
