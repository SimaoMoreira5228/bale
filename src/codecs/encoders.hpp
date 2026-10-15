#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <memory>
#include <span>

namespace bale {

class DeflateEncoder {
  public:
    [[nodiscard]] static Result<DeflateEncoder> create(int compressionLevel = 6);

    DeflateEncoder(DeflateEncoder&& other) noexcept;
    DeflateEncoder& operator=(DeflateEncoder&& other) noexcept;
    ~DeflateEncoder();

    [[nodiscard]] static std::size_t compressBound(std::size_t inputSize);
    [[nodiscard]] Result<std::size_t>
    compress(std::span<const std::byte> input, std::span<std::byte> output);

  private:
    struct State;

    explicit DeflateEncoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

}
