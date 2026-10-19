#include "crypto/secrets.hpp"

#include <sodium/core.h>
#include <sodium/utils.h>

#include <utility>

namespace bale::crypto {

SecretBytes::SecretBytes(std::byte* data, std::size_t size) noexcept : data_(data), size_(size) {
}

Result<SecretBytes> SecretBytes::make(std::size_t size) {
    if (sodium_init() < 0) {
        return fail(ErrorKind::Io, "libsodium init failed", 0);
    }

    if (size == 0) {
        return SecretBytes();
    }

    auto* raw = sodium_malloc(size);
    if (raw == nullptr) {
        return fail(ErrorKind::LimitExceeded, "secret storage allocation failed", size);
    }
    return SecretBytes(static_cast<std::byte*>(raw), size);
}

SecretBytes::~SecretBytes() {
    sodium_free(data_);
}

SecretBytes::SecretBytes(SecretBytes&& other) noexcept :
    data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {
}

SecretBytes& SecretBytes::operator=(SecretBytes&& other) noexcept {
    if (this != &other) {
        sodium_free(data_);

        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

std::span<const std::byte> SecretBytes::bytes() const {
    return {data_, size_};
}

std::span<std::byte> SecretBytes::mut() {
    return {data_, size_};
}

void SecretBytes::wipe() {
    if (data_ != nullptr) {
        sodium_memzero(data_, size_);
    }
}

}
