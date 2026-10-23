#include "checksum/crc.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

using namespace bale;

namespace {

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text));
}

class XorShift {
  public:
    std::uint64_t operator()() {
        state_ ^= state_ << 13;
        state_ ^= state_ >> 7;
        state_ ^= state_ << 17;
        return state_;
    }

  private:
    std::uint64_t state_ = 0x9E3779B97F4A7C15;
};

template <typename Checksum> void checkSplitUpdates(std::span<const std::byte> data) {
    const auto whole = Checksum::of(data);
    for (std::size_t split : {0U, 1U, 7U, 8U, 9U, 500U, 999U}) {
        Checksum crc;
        crc.update(data.first(split));
        crc.update({});
        crc.update(data.subspan(split));
        CHECK(crc.value() == whole);
    }
}

}

TEST_CASE("CRC-32 and CRC32C match their published check values") {
    CHECK(Crc32::of(bytesOf("123456789")) == 0xCBF43926);
    CHECK(Crc32c::of(bytesOf("123456789")) == 0xE3069283);
    CHECK(Crc32::of({}) == 0);
    CHECK(Crc32c::of({}) == 0);

    SUBCASE("RFC 3720 iSCSI vectors") {
        std::array<std::byte, 32> zeros{};
        CHECK(Crc32c::of(zeros) == 0x8A9136AA);

        std::array<std::byte, 32> ones{};
        ones.fill(std::byte{0xFF});
        CHECK(Crc32c::of(ones) == 0x62A8AB43);

        std::array<std::byte, 32> ascending{};
        for (std::size_t index = 0; index < ascending.size(); ++index) {
            ascending[index] = static_cast<std::byte>(index);
        }
        CHECK(Crc32c::of(ascending) == 0x46DD794E);
    }
}

TEST_CASE("incremental updates at unaligned split points equal a single pass") {
    std::vector<std::byte> data(1000);
    for (std::size_t index = 0; index < data.size(); ++index) {
        data[index] = static_cast<std::byte>(index * 31 + 7);
    }

    checkSplitUpdates<Crc32>(data);
    checkSplitUpdates<Crc32c>(data);
}

TEST_CASE("every available CRC kernel matches the portable reference") {
    std::vector<std::byte> data((std::size_t{1} << 20) + 16);
    XorShift random;
    for (std::byte& byte : data) {
        byte = static_cast<std::byte>(random());
    }

    for (CrcAlgorithm algorithm : {CrcAlgorithm::Crc32, CrcAlgorithm::Crc32c}) {
        const CrcKernel reference = portableCrcKernel(algorithm);
        std::vector<CrcKernel> kernels{reference};
        if (auto accelerated = acceleratedCrcKernel(algorithm)) {
            kernels.push_back(*accelerated);
        }

        const std::uint32_t check = algorithm == CrcAlgorithm::Crc32 ? 0xCBF43926 : 0xE3069283;
        for (const CrcKernel& kernel : kernels) {
            CAPTURE(kernel.name);
            CHECK(kernel.function(0, bytesOf("123456789")) == check);
            CHECK(kernel.function(0x1234, {}) == 0x1234);

            std::size_t mismatches = 0;
            for (int round = 0; round < 2000; ++round) {
                const std::size_t offset = random() % 16;
                const std::size_t length = random() % 4097;
                const auto seed = static_cast<std::uint32_t>(random());
                auto slice = std::span(data).subspan(offset, length);
                if (kernel.function(seed, slice) != reference.function(seed, slice)) {
                    ++mismatches;
                }
            }
            CHECK(mismatches == 0);

            for (std::size_t offset : {0U, 3U}) {
                auto slice = std::span(data).subspan(offset, std::size_t{1} << 20);
                CHECK(kernel.function(0, slice) == reference.function(0, slice));
            }
        }
    }
}
