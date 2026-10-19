#include "archive/encrypted.hpp"
#include "fuzz/memory_file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

void checkKeyslot(std::span<const std::byte> input) {
    auto slot = bale::archive::decodeKeyslot(input, 0);
    if (!slot) {
        return;
    }

    std::vector<std::byte> encoded;
    if (!bale::archive::encodeKeyslot(*slot, encoded)) {
        __builtin_trap();
    }
    auto again = bale::archive::decodeKeyslot(encoded, 0);
    if (!again) {
        __builtin_trap();
    }
    if (again->epoch != slot->epoch || again->kind != slot->kind) {
        __builtin_trap();
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    checkKeyslot(bale::fuzz::bytesOf(data, size));
    return 0;
}
