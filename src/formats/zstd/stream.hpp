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

namespace bale::zstd {

inline constexpr std::array<std::byte, 4> frameMagic{
    std::byte{0x28},
    std::byte{0xB5},
    std::byte{0x2F},
    std::byte{0xFD},
};

struct Limits {
    std::uint64_t maxOutputBytes = std::uint64_t{1} << 40;
    std::uint32_t maxWindowLog = 27;
    std::size_t chunkBytes = std::size_t{64} << 10;
};

[[nodiscard]] bool looksLikeZstd(std::span<const std::byte> head);

class Stream {
  public:
    [[nodiscard]] static Result<Stream> open(File file, const Limits& limits = {});

    [[nodiscard]] std::uint64_t outputBytes() const {
        return outputBytes_;
    }

    [[nodiscard]] Result<std::size_t> read(std::span<std::byte> out);

  private:
    Stream(FileInput input, const Limits& limits, ZstdDecoder decoder) :
        input_(std::move(input)), limits_(limits), decoder_(std::move(decoder)) {
    }

    [[nodiscard]] Result<std::size_t> decode(std::span<std::byte> out);

    FileInput input_;
    Limits limits_;
    ZstdDecoder decoder_;
    std::uint64_t outputBytes_ = 0;
    std::optional<Error> failure_;
    bool frameEnded_ = true;
};

}
