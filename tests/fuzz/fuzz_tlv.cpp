#include "format/tlv.hpp"
#include "fuzz/memory_file.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

constexpr int maxNesting = 4;
constexpr std::uint64_t maxListElements = 1024;

void checkLeb128(std::span<const std::byte> input) {
    auto decoded = bale::decodeLeb128(input);
    if (!decoded) {
        return;
    }

    std::array<std::byte, bale::maxLeb128Size> encoded{};
    std::size_t size = bale::encodeLeb128(decoded->value, encoded);
    if (size != decoded->size ||
        !std::ranges::equal(std::span(encoded).first(size), input.first(decoded->size))) {
        __builtin_trap();
    }
}

void walk(std::span<const std::byte> data, std::uint64_t offset, int depth);

void walkList(const bale::TlvField& field, int depth) {
    auto list = bale::TlvListReader::open(field, maxListElements);
    if (!list) {
        return;
    }

    std::span<const std::byte> element;
    std::uint64_t elementOffset = 0;
    while (true) {
        auto more = list->next(element, elementOffset);
        if (!more || !*more) {
            return;
        }
        walk(element, elementOffset, depth + 1);
    }
}

void walk(std::span<const std::byte> data, std::uint64_t offset, int depth) {
    if (depth > maxNesting) {
        return;
    }

    std::vector<std::byte> reencoded;
    bale::TlvWriter writer(reencoded);
    bale::TlvReader reader(data, offset);
    bale::TlvField field;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return;
        }
        if (!*more) {
            break;
        }

        if (field.value.data() < data.data() ||
            field.value.data() + field.value.size() > data.data() + data.size()) {
            __builtin_trap();
        }
        if (!writer.bytes(field.number, field.criticality, field.value)) {
            __builtin_trap();
        }

        static_cast<void>(bale::decodeTlvUnsigned(field));
        static_cast<void>(bale::decodeTlvSigned64(field));
        static_cast<void>(bale::skipUnknownField(field));
        walk(field.value, field.offset, depth + 1);
        walkList(field, depth);
    }

    if (!std::ranges::equal(reencoded, data)) {
        __builtin_trap();
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    checkLeb128(input);
    walk(input, 0, 0);
    return 0;
}
