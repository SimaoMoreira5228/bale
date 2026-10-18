#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <memory>
#include <span>

namespace bale {

inline constexpr int minLz4Level = 0;
inline constexpr int maxLz4Level = 12;

class Lz4FrameEncoder {
  public:
    [[nodiscard]] static Result<Lz4FrameEncoder> create(int compressionLevel = minLz4Level);

    Lz4FrameEncoder(Lz4FrameEncoder&& other) noexcept;
    Lz4FrameEncoder& operator=(Lz4FrameEncoder&& other) noexcept;
    ~Lz4FrameEncoder();

    [[nodiscard]] static std::size_t compressBound(std::size_t inputSize);
    [[nodiscard]] Result<std::size_t>
    compress(std::span<const std::byte> input, std::span<std::byte> output);

  private:
    struct State;

    explicit Lz4FrameEncoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

class Lz4FrameDecoder {
  public:
    [[nodiscard]] static Result<Lz4FrameDecoder> create();

    Lz4FrameDecoder(Lz4FrameDecoder&& other) noexcept;
    Lz4FrameDecoder& operator=(Lz4FrameDecoder&& other) noexcept;
    ~Lz4FrameDecoder();

    [[nodiscard]] Result<void>
    decompress(std::span<const std::byte> frame, std::span<std::byte> output);

  private:
    struct State;

    explicit Lz4FrameDecoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

}
