#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <memory>
#include <span>

namespace bale {

inline constexpr int minLzma2Level = 0;
inline constexpr int maxLzma2Level = 9;

class Lzma2Encoder {
  public:
    [[nodiscard]] static Result<Lzma2Encoder> create(int compressionLevel = 6);

    Lzma2Encoder(Lzma2Encoder&& other) noexcept;
    Lzma2Encoder& operator=(Lzma2Encoder&& other) noexcept;
    ~Lzma2Encoder();

    [[nodiscard]] static std::size_t compressBound(std::size_t inputSize);
    [[nodiscard]] Result<std::size_t>
    compress(std::span<const std::byte> input, std::span<std::byte> output);

  private:
    struct State;

    explicit Lzma2Encoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

}
