#include "io/byte_reader.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstddef>

using namespace bale;

namespace {

constexpr std::array sample{
    std::byte{0x01},
    std::byte{0x34},
    std::byte{0x12},
    std::byte{0x78},
    std::byte{0x56},
    std::byte{0x34},
    std::byte{0x12},
    std::byte{0xEF},
    std::byte{0xCD},
    std::byte{0xAB},
    std::byte{0x89},
    std::byte{0x67},
    std::byte{0x45},
    std::byte{0x23},
    std::byte{0x01},
};

}

TEST_CASE("ByteReader decodes little-endian integers in sequence") {
    ByteReader reader(sample);

    CHECK(reader.u8() == 0x01);
    CHECK(reader.u16le() == 0x1234);
    CHECK(reader.u32le() == 0x12345678);
    CHECK(reader.u64le() == 0x0123456789ABCDEF);
    CHECK(reader.empty());
}

TEST_CASE("ByteReader reports truncation with the absolute offset and does not advance") {
    ByteReader reader{std::span(sample).first(5), 1000};
    REQUIRE(reader.skip(3));

    auto value = reader.u32le();
    REQUIRE_FALSE(value);
    CHECK(value.error().kind == ErrorKind::Truncated);
    CHECK(value.error().offset == 1003);
    CHECK(reader.remaining() == 2);

    CHECK_FALSE(reader.bytes(3));
    CHECK_FALSE(reader.skip(3));
    CHECK(reader.bytes(2)->size() == 2);
    CHECK(reader.offset() == 1005);
}
