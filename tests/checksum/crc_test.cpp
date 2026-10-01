#include "checksum/crc.hpp"

#include <doctest/doctest.h>

#include <array>
#include <span>
#include <string_view>
#include <vector>

using namespace bale;

namespace {

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text));
}

}

TEST_CASE("CRC-32 and CRC32C match their published check values") {
    CHECK(Crc32::of(bytesOf("123456789")) == 0xCBF43926);
    CHECK(Crc32c::of(bytesOf("123456789")) == 0xE3069283);
    CHECK(Crc32::of({}) == 0);
    CHECK(Crc32c::of({}) == 0);
}

TEST_CASE("CRC32C matches the RFC 3720 iSCSI vectors") {
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

TEST_CASE("incremental updates at unaligned split points equal a single pass") {
    std::vector<std::byte> data(1000);
    for (std::size_t index = 0; index < data.size(); ++index) {
        data[index] = static_cast<std::byte>(index * 31 + 7);
    }
    auto whole = Crc32c::of(data);

    for (std::size_t split : {1U, 7U, 8U, 9U, 500U, 999U}) {
        Crc32c crc;
        crc.update(std::span(data).first(split));
        crc.update(std::span(data).subspan(split));
        CHECK(crc.value() == whole);
    }
}
