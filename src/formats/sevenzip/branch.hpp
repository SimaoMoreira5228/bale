#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale::sevenzip {

// Streaming x86 branch-converter (BCJ) decoder: converts absolute E8/E9
// displacements back to relative form. Single-coder BCJ folders and the
// BCJ stage of [main codec + BCJ] filter chains both decode through here.
//
// The transform reads the absolute stream position (K = position + 5) and
// keeps a small amount of state: recent skip positions decide suppression
// and conversion modes. All state lives in this object; `filter` may hold
// back up to four trailing bytes (an incomplete opcode + displacement),
// emitted by `flush` at end of stream. Positions count from folder start.
class BcjFilter {
  public:
    BcjFilter() = default;

    void reset();

    struct Step {
        std::size_t consumed = 0;
        std::size_t produced = 0;
    };

    [[nodiscard]] Result<Step>
    filter(std::span<const std::byte> input, std::span<std::byte> output);

    [[nodiscard]] Result<std::size_t> flush(std::span<std::byte> output);

    [[nodiscard]] std::uint64_t position() const {
        return position_;
    }

  private:
    [[nodiscard]] Result<void> noteSkip(std::uint64_t at, bool suppressed);
    [[nodiscard]] std::size_t skipCount(std::uint64_t from, std::uint64_t to) const;
    [[nodiscard]] bool skipped(std::uint64_t at) const;
    [[nodiscard]] bool suppressedAt(std::uint64_t at) const;
    [[nodiscard]] bool genuineAt(std::uint64_t at) const;

    std::vector<std::byte> pending_;
    std::size_t scan_ = 0;
    std::uint64_t position_ = 0;
    std::vector<std::uint64_t> skips_;
    std::vector<std::uint64_t> suppressions_;
};

}
