#include "format/tlv.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <vector>

using namespace bale;

namespace {

std::vector<std::byte> bytes(std::initializer_list<int> values) {
    std::vector<std::byte> out;
    for (int value : values) {
        out.push_back(static_cast<std::byte>(value));
    }
    return out;
}

ErrorKind leb128Error(std::initializer_list<int> values) {
    auto decoded = decodeLeb128(bytes(values));
    REQUIRE_FALSE(decoded);
    return decoded.error().kind;
}

Error tlvError(std::initializer_list<int> values) {
    auto data = bytes(values);
    TlvReader reader(data, 100);
    TlvField field;
    while (true) {
        auto next = reader.next(field);
        if (!next) {
            return next.error();
        }
        REQUIRE(*next);
    }
}

}

TEST_CASE("ULEB128 golden encodings round-trip at every width boundary") {
    struct Vector {
        std::uint64_t value;
        std::vector<std::byte> encoded;
    };
    const std::array vectors{
        Vector{0, bytes({0x00})},
        Vector{127, bytes({0x7F})},
        Vector{128, bytes({0x80, 0x01})},
        Vector{624485, bytes({0xE5, 0x8E, 0x26})},
        Vector{
            std::uint64_t{1} << 63,
            bytes({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01})
        },
        Vector{
            std::numeric_limits<std::uint64_t>::max(),
            bytes({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01})
        },
    };

    for (const auto& vector : vectors) {
        std::vector<std::byte> encoded;
        appendLeb128(encoded, vector.value);
        CHECK(encoded == vector.encoded);

        auto withTrailing = vector.encoded;
        withTrailing.push_back(std::byte{0xAA});
        auto decoded = decodeLeb128(withTrailing);
        REQUIRE(decoded);
        CHECK(decoded->value == vector.value);
        CHECK(decoded->size == vector.encoded.size());
    }
}

TEST_CASE("ULEB128 rejects non-minimal, overflowing, overlong and truncated encodings") {
    CHECK(leb128Error({0x80, 0x00}) == ErrorKind::Malformed);
    CHECK(leb128Error({0xFF, 0x80, 0x00}) == ErrorKind::Malformed);
    CHECK(
        leb128Error({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}) ==
        ErrorKind::Malformed
    );
    CHECK(
        leb128Error({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02}) ==
        ErrorKind::Malformed
    );
    CHECK(
        leb128Error({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}) ==
        ErrorKind::Malformed
    );
    CHECK(
        leb128Error({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x81, 0x00}) ==
        ErrorKind::Malformed
    );
    CHECK(leb128Error({}) == ErrorKind::Truncated);
    CHECK(leb128Error({0x80}) == ErrorKind::Truncated);
    CHECK(
        leb128Error({0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}) == ErrorKind::Truncated
    );
}

TEST_CASE("TLV writer and reader agree on the whitepaper golden bytes 02 02 AB CD 07 01 01") {
    auto golden = bytes({0x02, 0x02, 0xAB, 0xCD, 0x07, 0x01, 0x01});

    std::vector<std::byte> out;
    TlvWriter writer(out);
    REQUIRE(writer.bytes(1, Criticality::Noncritical, bytes({0xAB, 0xCD})));
    REQUIRE(writer.bytes(3, Criticality::Critical, bytes({0x01})));
    CHECK(out == golden);

    TlvReader reader(golden, 1000);
    TlvField field;
    REQUIRE(reader.next(field) == true);
    CHECK(field.number == 1);
    CHECK(field.criticality == Criticality::Noncritical);
    CHECK(field.offset == 1000);
    CHECK(std::vector(field.value.begin(), field.value.end()) == bytes({0xAB, 0xCD}));
    CHECK(skipUnknownField(field));

    REQUIRE(reader.next(field) == true);
    CHECK(field.number == 3);
    CHECK(field.criticality == Criticality::Critical);
    CHECK(field.offset == 1004);
    CHECK(decodeTlvUnsigned(field) == 1);
    auto unknown = skipUnknownField(field);
    REQUIRE_FALSE(unknown);
    CHECK(unknown.error().kind == ErrorKind::Unsupported);
    CHECK(unknown.error().offset == 1004);

    CHECK(reader.next(field) == false);
}

TEST_CASE("TLV round-trips the largest field number, empty values and multi-byte lengths") {
    std::vector<std::byte> large(300, std::byte{0x5A});
    std::vector<std::byte> out;
    TlvWriter writer(out);
    REQUIRE(writer.bytes(2, Criticality::Noncritical, {}));
    REQUIRE(
        writer.unsignedValue(200, Criticality::Critical, std::numeric_limits<std::uint64_t>::max())
    );
    REQUIRE(writer.bytes(maxTlvFieldNumber, Criticality::Critical, large));

    TlvReader reader(out);
    TlvField field;
    REQUIRE(reader.next(field) == true);
    CHECK(field.number == 2);
    CHECK(field.value.empty());

    REQUIRE(reader.next(field) == true);
    CHECK(field.number == 200);
    CHECK(decodeTlvUnsigned(field) == std::numeric_limits<std::uint64_t>::max());

    REQUIRE(reader.next(field) == true);
    CHECK(field.number == maxTlvFieldNumber);
    CHECK(field.criticality == Criticality::Critical);
    CHECK(field.value.size() == 300);

    CHECK(reader.next(field) == false);
}

TEST_CASE("TLV writer refuses out-of-order, duplicate and out-of-range field numbers") {
    std::vector<std::byte> out;
    TlvWriter writer(out);
    CHECK_FALSE(writer.bytes(0, Criticality::Noncritical, {}));
    CHECK_FALSE(writer.bytes(maxTlvFieldNumber + 1, Criticality::Noncritical, {}));
    REQUIRE(writer.bytes(5, Criticality::Noncritical, {}));
    CHECK_FALSE(writer.bytes(5, Criticality::Critical, {}));
    CHECK_FALSE(writer.unsignedValue(4, Criticality::Noncritical, 1));
    CHECK(out == bytes({0x0A, 0x00}));
}

TEST_CASE("TLV reader rejects hostile structures with the offset of the bad field") {
    auto outOfOrder = tlvError({0x04, 0x00, 0x02, 0x00});
    CHECK(outOfOrder.kind == ErrorKind::Malformed);
    CHECK(outOfOrder.offset == 102);

    CHECK(tlvError({0x02, 0x00, 0x02, 0x00}).kind == ErrorKind::Malformed);
    CHECK(tlvError({0x02, 0x00, 0x03, 0x00}).kind == ErrorKind::Malformed);
    CHECK(tlvError({0x00, 0x00}).kind == ErrorKind::Malformed);
    CHECK(tlvError({0x01, 0x00}).kind == ErrorKind::Malformed);
    CHECK(tlvError({0x80, 0x80, 0x80, 0x80, 0x04, 0x00}).kind == ErrorKind::Malformed);
    CHECK(tlvError({0x82, 0x00, 0x00}).kind == ErrorKind::Malformed);
    CHECK(tlvError({0x02, 0x80, 0x00}).kind == ErrorKind::Malformed);

    auto pastEnd = tlvError({0x02, 0x03, 0xAA, 0xBB});
    CHECK(pastEnd.kind == ErrorKind::Truncated);
    CHECK(pastEnd.offset == 102);

    CHECK(
        tlvError({0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}).kind ==
        ErrorKind::Truncated
    );
    CHECK(tlvError({0x02}).kind == ErrorKind::Truncated);
    CHECK(tlvError({0x82}).kind == ErrorKind::Truncated);
}

TEST_CASE("TLV unsigned values must be a single minimal ULEB128 with no trailing bytes") {
    auto data = bytes({0x02, 0x02, 0x05, 0x00, 0x04, 0x02, 0x80, 0x00});
    TlvReader reader(data);
    TlvField field;

    REQUIRE(reader.next(field) == true);
    CHECK(decodeTlvUnsigned(field).error().kind == ErrorKind::Malformed);

    REQUIRE(reader.next(field) == true);
    CHECK(decodeTlvUnsigned(field).error().kind == ErrorKind::Malformed);
}
