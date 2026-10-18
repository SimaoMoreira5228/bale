#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <memory>
#include <span>

namespace bale {

class ZstdEncoder {
  public:
    [[nodiscard]] static Result<ZstdEncoder> create(int compressionLevel = 3);

    ZstdEncoder(ZstdEncoder&& other) noexcept;
    ZstdEncoder& operator=(ZstdEncoder&& other) noexcept;
    ~ZstdEncoder();

    [[nodiscard]] static std::size_t compressBound(std::size_t inputSize);
    [[nodiscard]] Result<std::size_t>
    compress(std::span<const std::byte> input, std::span<std::byte> output);

  private:
    struct State;

    explicit ZstdEncoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

}
