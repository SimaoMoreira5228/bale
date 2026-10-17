#pragma once

#include "base/error.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace bale {

class FileInput {
  public:
    [[nodiscard]] static Result<FileInput> open(File file, std::size_t capacity);

    [[nodiscard]] std::span<const std::byte> pending() const {
        return pending_;
    }

    [[nodiscard]] std::uint64_t offset() const {
        return position_ - pending_.size();
    }

    [[nodiscard]] bool exhausted() const {
        return pending_.empty() && position_ == size_;
    }

    void consume(std::size_t count) {
        pending_ = pending_.subspan(count);
    }

    // NOTE: reads until at least `minimum` bytes (capped at the buffer size) are pending or the
    // file ends; reaching the end is not an error.
    [[nodiscard]] Result<void> fill(std::size_t minimum);

  private:
    FileInput(File file, std::uint64_t size, std::size_t capacity) :
        file_(std::move(file)), size_(size), buffer_(capacity) {
    }

    File file_;
    std::uint64_t size_;
    std::vector<std::byte> buffer_;
    std::span<const std::byte> pending_;
    std::uint64_t position_ = 0;
};

}
