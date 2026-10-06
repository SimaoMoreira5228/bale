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

class Source {
  public:
    [[nodiscard]] static Result<Source> open(File file);

    explicit Source(CompressedStream stream);

    [[nodiscard]] std::uint64_t position() const {
        return position_;
    }

    [[nodiscard]] bool seekable() const;

    [[nodiscard]] std::optional<std::uint64_t> remaining() const;

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
