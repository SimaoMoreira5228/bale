#pragma once

#include "base/endian.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace bale {

template <std::uint32_t ReflectedPolynomial> class Crc {
  public:
    void update(std::span<const std::byte> data) {
        std::uint32_t crc = state_;
        const std::byte* cursor = data.data();
        std::size_t length = data.size();

        while (length >= 8) {
            std::uint32_t low = loadLe<std::uint32_t>(cursor) ^ crc;
            std::uint32_t high = loadLe<std::uint32_t>(cursor + 4);
            crc = tables[7][low & 0xFF] ^ tables[6][(low >> 8) & 0xFF] ^
                tables[5][(low >> 16) & 0xFF] ^ tables[4][low >> 24] ^ tables[3][high & 0xFF] ^
                tables[2][(high >> 8) & 0xFF] ^ tables[1][(high >> 16) & 0xFF] ^
                tables[0][high >> 24];
            cursor += 8;
            length -= 8;
        }

        while (length > 0) {
            crc = tables[0][(crc ^ std::to_integer<std::uint32_t>(*cursor)) & 0xFF] ^ (crc >> 8);
            ++cursor;
            --length;
        }

        state_ = crc;
    }

    [[nodiscard]] std::uint32_t value() const {
        return ~state_;
    }

    [[nodiscard]] static std::uint32_t of(std::span<const std::byte> data) {
        Crc crc;
        crc.update(data);
        return crc.value();
    }

  private:
    using Table = std::array<std::uint32_t, 256>;

    static constexpr std::array<Table, 8> makeTables() {
        std::array<Table, 8> result{};
        for (std::uint32_t index = 0; index < 256; ++index) {
            std::uint32_t crc = index;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ ReflectedPolynomial : crc >> 1;
            }
            result[0][index] = crc;
        }

        for (std::size_t slice = 1; slice < 8; ++slice) {
            for (std::size_t index = 0; index < 256; ++index) {
                std::uint32_t previous = result[slice - 1][index];
                result[slice][index] = (previous >> 8) ^ result[0][previous & 0xFF];
            }
        }
        return result;
    }

    static constexpr std::array<Table, 8> tables = makeTables();

    std::uint32_t state_ = 0xFFFFFFFF;
};

using Crc32 = Crc<0xEDB88320>;

// PERF: CRC32C has SSE4.2 and ARMv8 instructions that are several times faster than slicing.
using Crc32c = Crc<0x82F63B78>;

}
