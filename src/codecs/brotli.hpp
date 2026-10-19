#pragma once

#include "base/error.hpp"
#include "codecs/decoders.hpp"

#include <cstddef>
#include <memory>
#include <span>

namespace bale {

inline constexpr int minBrotliLevel = 0;
inline constexpr int maxBrotliLevel = 11;

class BrotliEncoder {
  public:
    [[nodiscard]] static Result<BrotliEncoder> create(int compressionLevel = 11);

    BrotliEncoder(BrotliEncoder&& other) noexcept;
    BrotliEncoder& operator=(BrotliEncoder&& other) noexcept;
    ~BrotliEncoder();

    [[nodiscard]] static std::size_t compressBound(std::size_t inputSize);
    [[nodiscard]] Result<std::size_t>
    compress(std::span<const std::byte> input, std::span<std::byte> output);

  private:
    struct State;

    explicit BrotliEncoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

class BrotliDecoder {
  public:
    [[nodiscard]] static Result<BrotliDecoder> create();

    BrotliDecoder(BrotliDecoder&& other) noexcept;
    BrotliDecoder& operator=(BrotliDecoder&& other) noexcept;
    ~BrotliDecoder();

    [[nodiscard]] Result<DecodeStep>
    decompress(std::span<const std::byte> input, std::span<std::byte> output, bool finish);

    [[nodiscard]] Result<void> reset();

  private:
    struct State;

    explicit BrotliDecoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

}
