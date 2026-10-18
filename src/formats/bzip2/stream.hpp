#pragma once

#include "base/error.hpp"
#include "codecs/decoders.hpp"
#include "io/file.hpp"
#include "io/file_input.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace bale::bzip2 {

inline constexpr std::array<std::byte, 3> streamMagic{
    std::byte{'B'},
    std::byte{'Z'},
    std::byte{'h'},
};

struct Limits {
    std::uint64_t maxOutputBytes = std::uint64_t{1} << 40;
    std::size_t chunkBytes = std::size_t{64} << 10;
};

[[nodiscard]] bool looksLikeBzip2(std::span<const std::byte> head);

class Stream {
  public:
    [[nodiscard]] static Result<Stream> open(File file, const Limits& limits = {});

    [[nodiscard]] std::uint64_t streams() const {
        return streams_;
    }

    [[nodiscard]] std::uint64_t outputBytes() const {
        return outputBytes_;
    }

    [[nodiscard]] Result<std::size_t> read(std::span<std::byte> out);

  private:
    Stream(FileInput input, const Limits& limits, Bzip2Decoder decoder) :
        input_(std::move(input)), limits_(limits), decoder_(std::move(decoder)) {
    }

    [[nodiscard]] Result<std::size_t> decode(std::span<std::byte> out);
    [[nodiscard]] Result<bool> beginStream();

    FileInput input_;
    Limits limits_;
    Bzip2Decoder decoder_;
    std::uint64_t streams_ = 1;
    std::uint64_t outputBytes_ = 0;
    std::optional<Error> failure_;
};

}
