#pragma once

#include "base/error.hpp"
#include "formats/compressed/stream.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace bale::tar {

// NOTE: the bytes a tar reader walks through front to back: a seekable file, whose skips are free
// and whose size is known up front, or a decompressed stream that can only be read in order.
class Source {
  public:
    [[nodiscard]] static Result<Source> open(File file);

    explicit Source(CompressedStream stream);

    [[nodiscard]] std::uint64_t position() const {
        return position_;
    }

    [[nodiscard]] bool seekable() const;

    // NOTE: bytes left before the end, known only for a seekable file.
    [[nodiscard]] std::optional<std::uint64_t> remaining() const;

    // NOTE: fills out completely unless the source ends first; returns the count read.
    [[nodiscard]] Result<std::size_t> readFull(std::span<std::byte> out);

    [[nodiscard]] Result<void> skip(std::uint64_t count);

    // NOTE: a stream is drained to its end so every codec checksum and trailer is verified.
    [[nodiscard]] Result<void> finish();

  private:
    struct Seekable {
        File file;
        std::uint64_t size = 0;
    };

    explicit Source(Seekable seekable) : input_(std::move(seekable)) {
    }

    [[nodiscard]] Result<std::size_t> pull(std::span<std::byte> out);

    std::variant<Seekable, CompressedStream> input_;
    std::vector<std::byte> discard_;
    std::uint64_t position_ = 0;
};

}
