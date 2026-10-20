#include "archive/signatures.hpp"
#include "fuzz/memory_file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

void checkSignatureRecord(std::span<const std::byte> input) {
    auto signature = bale::archive::decodeSignature(input, 0);
    if (!signature) {
        return;
    }

    std::vector<std::byte> encoded;
    if (!bale::archive::encodeSignature(*signature, encoded)) {
        __builtin_trap();
    }
    auto again = bale::archive::decodeSignature(encoded, 0);
    if (!again) {
        __builtin_trap();
    }
    if (again->epoch != signature->epoch || again->signer != signature->signer ||
        again->signature != signature->signature) {
        __builtin_trap();
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    checkSignatureRecord(bale::fuzz::bytesOf(data, size));
    return 0;
}
