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

namespace bale::xz {

inline constexpr std::array<std::byte, 6> streamMagic{
    std::byte{0xFD},
    std::byte{0x37},
    std::byte{0x7A},
    std::byte{0x58},
    std::byte{0x5A},
    std::byte{0x00},
};

struct Limits {
    std::uint64_t maxOutputBytes = std::uint64_t{1} << 40;
    std::uint64_t memLimitBytes = std::uint64_t{256} << 20;
    std::size_t chunkBytes = std::size_t{64} << 10;
};

[[nodiscard]] bool looksLikeXz(std::span<const std::byte> head);

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
    Stream(FileInput input, const Limits& limits, XzDecoder decoder) :
        input_(std::move(input)), limits_(limits), decoder_(std::move(decoder)) {
    }

    [[nodiscard]] Result<std::size_t> decode(std::span<std::byte> out);
    [[nodiscard]] Result<bool> beginStream();

    FileInput input_;
    Limits limits_;
    XzDecoder decoder_;
    std::uint64_t streams_ = 1;
    std::uint64_t outputBytes_ = 0;
    std::optional<Error> failure_;
};

}
