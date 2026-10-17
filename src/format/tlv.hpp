#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale {

inline constexpr std::size_t maxLeb128Size = 10;
inline constexpr std::uint32_t maxTlvFieldNumber = (std::uint32_t{1} << 29) - 1;

struct Leb128 {
    std::uint64_t value = 0;
    std::size_t size = 0;
};

[[nodiscard]] Result<Leb128>
decodeLeb128(std::span<const std::byte> data, std::uint64_t baseOffset = 0);

[[nodiscard]] std::size_t
encodeLeb128(std::uint64_t value, std::span<std::byte, maxLeb128Size> target);

void appendLeb128(std::vector<std::byte>& out, std::uint64_t value);

enum class Criticality : std::uint8_t {
    Noncritical,
    Critical,
};

struct TlvField {
    std::uint32_t number = 0;
    Criticality criticality = Criticality::Noncritical;
    std::span<const std::byte> value;
    std::uint64_t offset = 0;
};

class TlvReader {
  public:
    explicit TlvReader(std::span<const std::byte> data, std::uint64_t baseOffset = 0) :
        data_(data), base_(baseOffset) {
    }

    [[nodiscard]] Result<bool> next(TlvField& field);

  private:
    std::span<const std::byte> data_;
    std::uint64_t base_ = 0;
    std::size_t pos_ = 0;
    std::uint32_t lastNumber_ = 0;
};

[[nodiscard]] Result<void> skipUnknownField(const TlvField& field);

[[nodiscard]] Result<std::uint64_t> decodeTlvUnsigned(const TlvField& field);

[[nodiscard]] Result<std::int64_t> decodeTlvSigned64(const TlvField& field);

[[nodiscard]] Result<void> requireCriticality(const TlvField& field, Criticality expected);

class TlvListReader {
  public:
    [[nodiscard]] static Result<TlvListReader> open(const TlvField& field, std::uint64_t maxCount);

    [[nodiscard]] std::uint64_t count() const {
        return count_;
    }

    [[nodiscard]] Result<bool> next(std::span<const std::byte>& element, std::uint64_t& offset);

  private:
    TlvListReader(std::span<const std::byte> data, std::uint64_t baseOffset, std::uint64_t count) :
        data_(data), base_(baseOffset), count_(count) {
    }

    std::span<const std::byte> data_;
    std::uint64_t base_ = 0;
    std::uint64_t count_ = 0;
    std::uint64_t read_ = 0;
    std::size_t pos_ = 0;
};

void appendTlvListElement(std::vector<std::byte>& out, std::span<const std::byte> element);

class TlvWriter {
  public:
    explicit TlvWriter(std::vector<std::byte>& out) : out_(&out) {
    }

    [[nodiscard]] Result<void>
    bytes(std::uint32_t number, Criticality criticality, std::span<const std::byte> value);

    [[nodiscard]] Result<void>
    unsignedValue(std::uint32_t number, Criticality criticality, std::uint64_t value);

    [[nodiscard]] Result<void>
    signed64(std::uint32_t number, Criticality criticality, std::int64_t value);

  private:
    [[nodiscard]] Result<void>
    beginField(std::uint32_t number, Criticality criticality, std::uint64_t length);

    std::vector<std::byte>* out_;
    std::uint32_t lastNumber_ = 0;
};

}
