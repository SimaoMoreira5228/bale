#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <span>

namespace bale::crypto {

// NOTE: SecretBytes owns libsodium-managed storage (guard pages and a locking
// attempt where the platform allows it) and wipes on destruction. Non-empty
// instances only come from make, which reports init and allocation failures;
// the default state is empty and infallible.
class SecretBytes {
  public:
    SecretBytes() noexcept = default;

    ~SecretBytes();

    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;

    SecretBytes(SecretBytes&& other) noexcept;
    SecretBytes& operator=(SecretBytes&& other) noexcept;

    [[nodiscard]] static Result<SecretBytes> make(std::size_t size);

    [[nodiscard]] std::span<const std::byte> bytes() const;
    [[nodiscard]] std::span<std::byte> mut();

    [[nodiscard]] std::size_t size() const {
        return size_;
    }

    void wipe();

  private:
    SecretBytes(std::byte* data, std::size_t size) noexcept;

    std::byte* data_ = nullptr;
    std::size_t size_ = 0;
};

}
