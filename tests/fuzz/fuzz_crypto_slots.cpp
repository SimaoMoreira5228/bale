#include "crypto/crypto.hpp"
#include "fuzz/memory_file.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t maxSlotBytes = 1024;
constexpr std::string_view password = "fuzz-password";

bale::crypto::KdfParams fuzzParams() {
    return {.opslimit = 1, .memlimitBytes = 8192};
}

void checkPasswordSlot(std::span<const std::byte> input) {
    if (input.size() < bale::crypto::saltSize + bale::crypto::nonceSize) {
        return;
    }

    bale::crypto::PasswordSlot slot;
    slot.epoch = 1;
    slot.opslimit = fuzzParams().opslimit;
    slot.memlimitBytes = fuzzParams().memlimitBytes;
    std::ranges::copy(input.first(bale::crypto::saltSize), slot.salt.begin());
    std::ranges::copy(
        input.subspan(bale::crypto::saltSize, bale::crypto::nonceSize),
        slot.nonce.begin()
    );

    auto wrapped = input.subspan(bale::crypto::saltSize + bale::crypto::nonceSize);
    wrapped = wrapped.first(std::min(wrapped.size(), maxSlotBytes));
    slot.wrapped.assign(wrapped.begin(), wrapped.end());

    std::span<const std::byte> passwordBytes(
        reinterpret_cast<const std::byte*>(password.data()),
        password.size()
    );
    static_cast<void>(bale::crypto::unwrapPasswordKey(slot, passwordBytes));
}

void checkRecipientSlot(std::span<const std::byte> input) {
    static auto pair = bale::crypto::makeKeyPair();
    if (!pair) {
        return;
    }

    auto sealed = input.first(std::min(input.size(), maxSlotBytes));
    bale::crypto::RecipientSlot slot;
    slot.sealed.assign(sealed.begin(), sealed.end());

    static_cast<void>(
        bale::crypto::unwrapRecipientKey(slot, pair->publicKey, pair->secretKey.bytes())
    );
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    if (input.empty()) {
        return 0;
    }

    if ((std::to_integer<unsigned>(input[0]) & 1) == 0) {
        checkPasswordSlot(input.subspan(1));
    } else {
        checkRecipientSlot(input.subspan(1));
    }
    return 0;
}
