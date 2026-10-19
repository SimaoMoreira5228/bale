#include "crypto/crypto.hpp"
#include "fuzz/memory_file.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

constexpr std::size_t maxPlaintext = 4096;

void checkRoundTrip(std::span<const std::byte> input) {
    if (input.size() < bale::crypto::keySize + bale::crypto::nonceSize + 1) {
        return;
    }

    auto key = input.first(bale::crypto::keySize);
    auto nonce = input.subspan(bale::crypto::keySize, bale::crypto::nonceSize);
    auto body = input.subspan(bale::crypto::keySize + bale::crypto::nonceSize);
    auto plaintext = body.first(std::min(body.size(), maxPlaintext));

    auto boxed = bale::crypto::seal(key, nonce, plaintext, body);
    if (!boxed) {
        return;
    }

    auto back = bale::crypto::open(key, nonce, *boxed, body);
    if (!back) {
        __builtin_trap();
    }
    if (!std::ranges::equal(*back, plaintext)) {
        __builtin_trap();
    }

    static_cast<void>(bale::crypto::open(key, nonce, body, body));
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    checkRoundTrip(bale::fuzz::bytesOf(data, size));
    return 0;
}
