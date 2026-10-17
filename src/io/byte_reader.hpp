#pragma once

#include "base/error.hpp"
#include "io/endian.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace bale {

class ByteReader {
  public:
    explicit constexpr ByteReader(std::span<const std::byte> data, std::uint64_t baseOffset = 0) :
        data_(data), base_(baseOffset) {
    }

    [[nodiscard]] constexpr std::size_t position() const {
        return pos_;
    }

    [[nodiscard]] constexpr std::size_t remaining() const {
        return data_.size() - pos_;
    }

    [[nodiscard]] constexpr bool empty() const {
        return pos_ == data_.size();
    }

    [[nodiscard]] constexpr std::uint64_t offset() const {
        return base_ + pos_;
    }

    [[nodiscard]] constexpr std::span<const std::byte> rest() const {
        return data_.subspan(pos_);
    }

    [[nodiscard]] Result<std::span<const std::byte>> bytes(std::size_t count) {
        if (count > remaining()) {
            return fail(ErrorKind::Truncated, "unexpected end of data", offset());
        }

        auto taken = data_.subspan(pos_, count);
        pos_ += count;
        return taken;
    }

    [[nodiscard]] Result<void> skip(std::size_t count) {
        if (count > remaining()) {
            return fail(ErrorKind::Truncated, "unexpected end of data", offset());
        }

        pos_ += count;
        return {};
    }

    [[nodiscard]] Result<std::uint8_t> u8() {
        return read<std::uint8_t>();
    }

    [[nodiscard]] Result<std::uint16_t> u16le() {
        return read<std::uint16_t>();
    }

    [[nodiscard]] Result<std::uint32_t> u32le() {
        return read<std::uint32_t>();
    }

    [[nodiscard]] Result<std::uint64_t> u64le() {
        return read<std::uint64_t>();
    }

  private:
    template <std::unsigned_integral T> [[nodiscard]] Result<T> read() {
        if (sizeof(T) > remaining()) {
            return fail(ErrorKind::Truncated, "unexpected end of data", offset());
        }

        T value = loadLe<T>(data_.data() + pos_);
        pos_ += sizeof(T);
        return value;
    }

    std::span<const std::byte> data_;
    std::uint64_t base_ = 0;
    std::size_t pos_ = 0;
};

}
