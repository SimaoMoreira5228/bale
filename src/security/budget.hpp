#pragma once

#include "base/checked.hpp"
#include "base/error.hpp"

#include <cstdint>

namespace bale {

struct Limits {
    std::uint64_t maxEntries = 10'000'000;
    std::uint64_t maxTotalBytes = std::uint64_t{1} << 40;
    std::uint64_t maxEntryBytes = std::uint64_t{1} << 38;
    std::uint32_t maxPathBytes = 4096;
    std::uint32_t maxDepth = 256;
    std::uint64_t compressionRatioWarning = 1000;
};

class Budget {
  public:
    explicit constexpr Budget(const Limits& limits) : limits_(limits) {
    }

    [[nodiscard]] constexpr const Limits& limits() const {
        return limits_;
    }

    [[nodiscard]] constexpr std::uint64_t entries() const {
        return entries_;
    }

    [[nodiscard]] constexpr std::uint64_t totalBytes() const {
        return totalBytes_;
    }

    [[nodiscard]] constexpr std::uint64_t entryBytes() const {
        return entryBytes_;
    }

    [[nodiscard]] constexpr Result<void> chargeEntry() {
        if (entries_ >= limits_.maxEntries) {
            return fail(ErrorKind::LimitExceeded, "entry count limit exceeded");
        }

        ++entries_;
        entryBytes_ = 0;
        return {};
    }

    [[nodiscard]] constexpr Result<void> checkDeclaredSize(std::uint64_t size) const {
        if (size > limits_.maxEntryBytes) {
            return fail(ErrorKind::LimitExceeded, "entry size limit exceeded");
        }

        auto total = checkedAdd(totalBytes_, size);
        if (!total || *total > limits_.maxTotalBytes) {
            return fail(ErrorKind::LimitExceeded, "total decoded size limit exceeded");
        }
        return {};
    }

    [[nodiscard]] constexpr Result<void> chargeBytes(std::uint64_t count) {
        auto entry = checkedAdd(entryBytes_, count);
        if (!entry || *entry > limits_.maxEntryBytes) {
            return fail(ErrorKind::LimitExceeded, "entry size limit exceeded");
        }

        auto total = checkedAdd(totalBytes_, count);
        if (!total || *total > limits_.maxTotalBytes) {
            return fail(ErrorKind::LimitExceeded, "total decoded size limit exceeded");
        }

        entryBytes_ = *entry;
        totalBytes_ = *total;
        return {};
    }

    [[nodiscard]] constexpr bool
    compressionRatioExceeded(std::uint64_t compressed, std::uint64_t decoded) const {
        auto allowed = checkedMul(compressed, limits_.compressionRatioWarning);
        if (!allowed) {
            return false;
        }
        return decoded > *allowed;
    }

  private:
    Limits limits_;
    std::uint64_t entries_ = 0;
    std::uint64_t totalBytes_ = 0;
    std::uint64_t entryBytes_ = 0;
};

}
