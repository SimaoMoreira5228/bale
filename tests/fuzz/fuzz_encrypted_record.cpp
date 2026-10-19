#include "archive/encrypted.hpp"
#include "crypto/crypto.hpp"
#include "fuzz/memory_file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

bale::crypto::SecretBytes& testKey() {
    static auto key = []() {
        auto made = bale::crypto::SecretBytes::make(bale::crypto::keySize);
        if (!made) {
            __builtin_trap();
        }
        bale::crypto::SecretBytes out(std::move(*made));
        std::ranges::fill(out.mut(), std::byte{0x5A});
        return out;
    }();
    return key;
}

void checkEncryptedData(std::span<const std::byte> input) {
    if (input.size() < bale::archive::encryptedDataHeaderSize + bale::crypto::tagSize) {
        return;
    }
    bale::archive::ObjectId object{};
    std::ranges::copy(input.first(32), object.begin());
    std::uint64_t epoch = 1;
    std::array<std::byte, 24> nonce{};
    std::ranges::copy(input.subspan(40, 24), nonce.begin());
    std::span<const std::byte> boxed = input.subspan(bale::archive::encryptedDataHeaderSize);

    std::array<std::byte, 16> archiveId{};
    auto aad = bale::archive::dataAad(
        std::span<const std::byte, 16>(archiveId.data(), 16),
        object,
        bale::CodecId::Raw,
        epoch
    );
    static_cast<void>(bale::crypto::open(testKey().bytes(), nonce, boxed, aad));
}

void checkRoundTrip(std::span<const std::byte> input) {
    if (input.empty() || input.size() > 4096) {
        return;
    }
    bale::archive::ObjectId object{};
    std::ranges::fill(object, std::byte{0x11});
    std::array<std::byte, 16> archiveId{};
    auto nonce = bale::crypto::makeNonce();
    if (!nonce) {
        return;
    }
    auto aad = bale::archive::dataAad(
        std::span<const std::byte, 16>(archiveId.data(), 16),
        object,
        bale::CodecId::Raw,
        1
    );
    auto sealed = bale::crypto::seal(testKey().bytes(), *nonce, input, aad);
    if (!sealed) {
        return;
    }
    auto back = bale::crypto::open(testKey().bytes(), *nonce, *sealed, aad);
    if (!back) {
        __builtin_trap();
    }
    if (!std::ranges::equal(*back, input)) {
        __builtin_trap();
    }
    // NOTE: flipping one sealed byte must fail authentication, never return plaintext.
    if (!sealed->empty()) {
        (*sealed)[0] = static_cast<std::byte>((*sealed)[0] ^ std::byte{0x01});
        auto tampered = bale::crypto::open(testKey().bytes(), *nonce, *sealed, aad);
        if (tampered) {
            __builtin_trap();
        }
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    checkEncryptedData(input);
    checkRoundTrip(input);
    return 0;
}
