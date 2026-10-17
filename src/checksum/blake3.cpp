#include "checksum/blake3.hpp"

#include <new>

#include <blake3.h>

namespace bale {

namespace {

template <typename Storage> blake3_hasher* hasherIn(Storage& storage) {
    static_assert(sizeof(blake3_hasher) <= sizeof(Storage));
    static_assert(alignof(blake3_hasher) <= 8);
    return std::launder(reinterpret_cast<blake3_hasher*>(storage.data()));
}

template <typename Storage> const blake3_hasher* hasherIn(const Storage& storage) {
    return std::launder(reinterpret_cast<const blake3_hasher*>(storage.data()));
}

}

Blake3::Blake3(HashDomain domain) {
    auto* hasher = ::new (static_cast<void*>(state_.data())) blake3_hasher;
    auto context = hashContext(domain);
    blake3_hasher_init_derive_key_raw(hasher, context.data(), context.size());
}

void Blake3::update(std::span<const std::byte> data) {
    blake3_hasher_update(hasherIn(state_), data.data(), data.size());
}

Blake3Digest Blake3::digest() const {
    Blake3Digest out{};
    blake3_hasher_finalize(
        hasherIn(state_),
        reinterpret_cast<std::uint8_t*>(out.data()),
        out.size()
    );
    return out;
}

void Blake3::reset() {
    blake3_hasher_reset(hasherIn(state_));
}

Blake3Digest Blake3::of(HashDomain domain, std::span<const std::byte> data) {
    Blake3 hasher(domain);
    hasher.update(data);
    return hasher.digest();
}

}
