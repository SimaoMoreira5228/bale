#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace bale {

enum class CrcAlgorithm : std::uint8_t {
    Crc32,
    Crc32c,
};

using CrcFunction = std::uint32_t (*)(std::uint32_t crc, std::span<const std::byte> data);

struct CrcKernel {
    std::string_view name;
    CrcFunction function = nullptr;
};

[[nodiscard]] CrcKernel portableCrcKernel(CrcAlgorithm algorithm);

[[nodiscard]] std::optional<CrcKernel> acceleratedCrcKernel(CrcAlgorithm algorithm);

template <CrcAlgorithm Algorithm> class Crc {
  public:
    void update(std::span<const std::byte> data);

    [[nodiscard]] std::uint32_t value() const {
        return value_;
    }

    [[nodiscard]] static std::uint32_t of(std::span<const std::byte> data) {
        Crc crc;
        crc.update(data);
        return crc.value();
    }

  private:
    std::uint32_t value_ = 0;
};

extern template class Crc<CrcAlgorithm::Crc32>;
extern template class Crc<CrcAlgorithm::Crc32c>;

using Crc32 = Crc<CrcAlgorithm::Crc32>;
using Crc32c = Crc<CrcAlgorithm::Crc32c>;

}
