#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace bale {

inline constexpr std::size_t blake3DigestSize = 32;

using Blake3Digest = std::array<std::byte, blake3DigestSize>;

enum class HashDomain : std::uint8_t {
    Chunk,
    Manifest,
    Index,
    Commit,
};

// NOTE: these contexts are part of the wire format; changing one changes every digest of that kind.
[[nodiscard]] constexpr std::string_view hashContext(HashDomain domain) {
    switch (domain) {
    case HashDomain::Chunk:
        return "bale 2026-10-17 v1 chunk";
    case HashDomain::Manifest:
        return "bale 2026-10-17 v1 manifest";
    case HashDomain::Index:
        return "bale 2026-10-17 v1 index";
    case HashDomain::Commit:
        return "bale 2026-10-17 v1 commit";
    }
    return {};
}

class Blake3 {
  public:
    explicit Blake3(HashDomain domain);

    void update(std::span<const std::byte> data);

    [[nodiscard]] Blake3Digest digest() const;

    void reset();

    [[nodiscard]] static Blake3Digest of(HashDomain domain, std::span<const std::byte> data);

  private:
    alignas(8) std::array<std::byte, 1920> state_{};
};

}
