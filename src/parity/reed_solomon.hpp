#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace bale::parity {

// Cauchy Reed-Solomon over GF(2^8) with primitive polynomial 0x11D and generator 2.
// The full (data + parity) x data encoding matrix is [I; C] where C[j][i] =
// inv(x_j ^ y_i), y_i = i, x_j = 255 - j. Every square submatrix of a Cauchy
// matrix is invertible, so any budgeted erasure pattern recovers. This is the
// property naive Vandermonde rows lack: some of their minors are singular over
// characteristic 2, and a few erasure patterns would refuse to decode.
inline constexpr std::uint32_t maxTotalShards = 256;
inline constexpr std::size_t maxShardBytes = std::size_t{64} << 20;
inline constexpr std::uint32_t gfPrimitivePolynomial = 0x11D;

namespace gf {

[[nodiscard]] std::uint8_t multiply(std::uint8_t a, std::uint8_t b);
[[nodiscard]] Result<std::uint8_t> inverse(std::uint8_t value);
[[nodiscard]] std::uint8_t exp(int exponent);
[[nodiscard]] Result<std::uint8_t> log(std::uint8_t value);

}

// Erasure coder: k data shards plus m parity shards, each shard the same byte
// length. No allocation inside encode/verify/repair; the caller owns every
// buffer, including the repair scratch area sized by scratchBytes().
class ReedSolomon {
  public:
    [[nodiscard]] static Result<ReedSolomon>
    make(std::uint32_t dataShards, std::uint32_t parityShards);

    [[nodiscard]] static Result<std::size_t>
    scratchBytes(std::uint32_t dataShards, std::uint32_t parityShards);

    [[nodiscard]] std::uint32_t data() const {
        return data_;
    }

    [[nodiscard]] std::uint32_t parity() const {
        return parity_;
    }

    [[nodiscard]] std::uint32_t total() const {
        return data_ + parity_;
    }

    // Fill every parity shard from the data shards.
    [[nodiscard]] Result<void> encode(
        std::span<const std::span<const std::byte>> data,
        std::span<const std::span<std::byte>> parity
    ) const;

    // Recompute parity and compare; false means at least one shard differs.
    [[nodiscard]] Result<bool> verify(
        std::span<const std::span<const std::byte>> data,
        std::span<const std::span<const std::byte>> parity
    ) const;

    // Recover missing shards in place. missing lists the indices of the shards
    // to rebuild; every entry must still point at a writable buffer of full
    // shard size. More missing shards than parity() refuses with Integrity and
    // leaves every output buffer untouched.
    [[nodiscard]] Result<void> repair(
        std::span<const std::span<std::byte>> shards,
        std::span<const std::uint32_t> missing,
        std::span<std::byte> scratch
    ) const;

  private:
    ReedSolomon(std::uint32_t dataShards, std::uint32_t parityShards) :
        data_(dataShards), parity_(parityShards) {
    }

    std::uint32_t data_ = 0;
    std::uint32_t parity_ = 0;
};

}
