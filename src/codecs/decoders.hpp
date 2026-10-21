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

    [[nodiscard]] Result<void> setDictionary(std::span<const std::byte> history);

  private:
    struct State;

    explicit Inflater(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

struct ZstdLimits {
    std::uint32_t maxWindowLog = 27;
};

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

struct XzLimits {
    std::uint64_t memLimitBytes = std::uint64_t{256} << 20;
};

class XzDecoder {
  public:
    [[nodiscard]] static Result<XzDecoder> create(const XzLimits& limits = {});

    XzDecoder(XzDecoder&& other) noexcept;
    XzDecoder& operator=(XzDecoder&& other) noexcept;
    ~XzDecoder();

    [[nodiscard]] Result<DecodeStep>
    decompress(std::span<const std::byte> input, std::span<std::byte> output, bool finish);

    [[nodiscard]] Result<void> reset();

    [[nodiscard]] bool streamEnded() const;

  private:
    struct State;

    explicit XzDecoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

class Bzip2Decoder {
  public:
    [[nodiscard]] static Result<Bzip2Decoder> create();

    Bzip2Decoder(Bzip2Decoder&& other) noexcept;
    Bzip2Decoder& operator=(Bzip2Decoder&& other) noexcept;
    ~Bzip2Decoder();

    [[nodiscard]] Result<DecodeStep>
    decompress(std::span<const std::byte> input, std::span<std::byte> output);

    [[nodiscard]] Result<void> reset();

    [[nodiscard]] bool streamEnded() const;

  private:
    struct State;

    explicit Bzip2Decoder(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

}
