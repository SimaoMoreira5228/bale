#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace bale {

struct DecodeStep {
    std::size_t consumed = 0;
    std::size_t produced = 0;
    bool finished = false;
};

class Inflater {
  public:
    [[nodiscard]] static Result<Inflater> create();

    Inflater(Inflater&& other) noexcept;
    Inflater& operator=(Inflater&& other) noexcept;
    ~Inflater();

    [[nodiscard]] Result<DecodeStep>
    decompress(std::span<const std::byte> input, std::span<std::byte> output);

    [[nodiscard]] Result<void> reset();

  private:
    struct State;

    explicit Inflater(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

struct ZstdLimits {
    std::uint32_t maxWindowLog = 27;
};

// NOTE: finished marks the end of one frame; further input continues with the next frame.
class ZstdDecoder {
  public:
    [[nodiscard]] static Result<ZstdDecoder> create(const ZstdLimits& limits = {});

    ZstdDecoder(ZstdDecoder&& other) noexcept;
    ZstdDecoder& operator=(ZstdDecoder&& other) noexcept;
    ~ZstdDecoder();

    [[nodiscard]] Result<DecodeStep>
    decompress(std::span<const std::byte> input, std::span<std::byte> output);

    [[nodiscard]] Result<void> reset();

  private:
    struct State;

    explicit ZstdDecoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

}
