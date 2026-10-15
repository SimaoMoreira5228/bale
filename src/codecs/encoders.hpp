#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace bale {

enum class EncodeFlush : std::uint8_t {
    None,
    Sync,
    Finish,
};

struct EncodeStep {
    std::size_t consumed = 0;
    std::size_t produced = 0;
    bool finished = false;
};

class DeflateEncoder {
  public:
    [[nodiscard]] static Result<DeflateEncoder> create(int compressionLevel = 6);

    DeflateEncoder(DeflateEncoder&& other) noexcept;
    DeflateEncoder& operator=(DeflateEncoder&& other) noexcept;
    ~DeflateEncoder();

    [[nodiscard]] static std::size_t compressBound(std::size_t inputSize);
    [[nodiscard]] Result<std::size_t>
    compress(std::span<const std::byte> input, std::span<std::byte> output);

    [[nodiscard]] Result<EncodeStep>
    stream(std::span<const std::byte> input, std::span<std::byte> output, EncodeFlush flush);

    [[nodiscard]] Result<void> reset();

  private:
    struct State;

    explicit DeflateEncoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

class ZstdEncoder {
  public:
    [[nodiscard]] static Result<ZstdEncoder>
    create(int compressionLevel = 3, bool contentChecksum = false);

    ZstdEncoder(ZstdEncoder&& other) noexcept;
    ZstdEncoder& operator=(ZstdEncoder&& other) noexcept;
    ~ZstdEncoder();

    [[nodiscard]] static std::size_t compressBound(std::size_t inputSize);
    [[nodiscard]] Result<std::size_t>
    compress(std::span<const std::byte> input, std::span<std::byte> output);

    [[nodiscard]] Result<EncodeStep>
    stream(std::span<const std::byte> input, std::span<std::byte> output, EncodeFlush flush);

  private:
    struct State;

    explicit ZstdEncoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

}
