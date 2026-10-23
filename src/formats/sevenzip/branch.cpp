#include "formats/sevenzip/branch.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <algorithm>

namespace bale::sevenzip {

namespace {

constexpr std::uint8_t opCall = 0xE8;
constexpr std::uint8_t opJump = 0xE9;
constexpr std::size_t dispBytes = 4;
constexpr std::size_t opcodeWindow = 5;
constexpr std::size_t maxHistory = 32;

bool isBranch(std::byte value) {
    auto byte = static_cast<std::uint8_t>(value);
    return byte == opCall || byte == opJump;
}

std::uint32_t topByte(std::uint32_t value) {
    return value >> 24;
}

bool convertible(std::uint32_t value) {
    std::uint32_t top = topByte(value);
    return top == 0x00 || top == 0xFF;
}

std::uint32_t loadDisp(std::span<const std::byte> at) {
    return loadLe<std::uint32_t>(at.data());
}

void storeDisp(std::span<std::byte> at, std::uint32_t value) {
    storeLe(at.data(), value);
}

bool oddByte(std::uint32_t value) {
    return (value & 0xFF) != 0;
}

}

void BcjFilter::reset() {
    pending_.clear();
    scan_ = 0;
    position_ = 0;
    skips_.clear();
    suppressions_.clear();
}

Result<void> BcjFilter::noteSkip(std::uint64_t at, bool suppressed) {
    skips_.push_back(at);
    if (suppressed) {
        suppressions_.push_back(at);
    }

    if (skips_.size() > maxHistory) {
        skips_.erase(skips_.begin());
    }
    if (suppressions_.size() > maxHistory) {
        suppressions_.erase(suppressions_.begin());
    }
    return {};
}

bool BcjFilter::skipped(std::uint64_t at) const {
    return std::find(skips_.begin(), skips_.end(), at) != skips_.end();
}

bool BcjFilter::suppressedAt(std::uint64_t at) const {
    return std::find(suppressions_.begin(), suppressions_.end(), at) != suppressions_.end();
}

bool BcjFilter::genuineAt(std::uint64_t at) const {
    return skipped(at) && !suppressedAt(at);
}

std::size_t BcjFilter::skipCount(std::uint64_t from, std::uint64_t to) const {
    std::size_t count = 0;
    for (std::uint64_t at = from;; ++at) {
        if (skipped(at)) {
            ++count;
        }
        if (at == to) {
            break;
        }
    }
    return count;
}

Result<BcjFilter::Step>
BcjFilter::filter(std::span<const std::byte> input, std::span<std::byte> output) {
    auto room = checkedAdd(pending_.size(), input.size());
    if (!room) {
        return fail(ErrorKind::LimitExceeded, "7z BCJ input exceeds buffer limit");
    }
    pending_.insert(pending_.end(), input.begin(), input.end());

    while (scan_ + opcodeWindow <= pending_.size()) {
        auto base = checkedAdd(position_, scan_);
        if (!base) {
            return fail(ErrorKind::Malformed, "7z BCJ position overflows");
        }
        std::uint64_t at = *base;
        if (!isBranch(pending_[scan_])) {
            ++scan_;
            continue;
        }

        std::uint32_t value = loadDisp(std::span(pending_).subspan(scan_ + 1, dispBytes));
        if (!convertible(value)) {
            auto noted = noteSkip(at, false);
            if (!noted) {
                return std::unexpected(noted.error());
            }
            ++scan_;
            continue;
        }

        bool near1 = at >= 1 && skipped(at - 1);
        bool near2 = at >= 2 && skipped(at - 2);
        bool near3 = at >= 3 && skipped(at - 3);
        std::size_t nearCount = (near1 ? 1U : 0U) + (near2 ? 1U : 0U) + (near3 ? 1U : 0U);
        if (nearCount >= 2) {
            auto noted = noteSkip(at, true);
            if (!noted) {
                return std::unexpected(noted.error());
            }
            ++scan_;
            continue;
        }

        bool at3 = at >= 3 && skipped(at - 3);
        bool at4 = at >= 4 && skipped(at - 4);
        bool at5 = at >= 5 && skipped(at - 5);
        bool at6 = at >= 6 && skipped(at - 6);
        if (at3 && at5 && at6 && !at4) {
            auto noted = noteSkip(at, true);
            if (!noted) {
                return std::unexpected(noted.error());
            }
            ++scan_;
            continue;
        }

        auto key = checkedAdd(at, std::uint64_t{opcodeWindow});
        if (!key) {
            return fail(ErrorKind::Malformed, "7z BCJ position overflows");
        }
        std::uint32_t key0 = static_cast<std::uint32_t>(*key & 0xFF);
        std::uint32_t key1 = static_cast<std::uint32_t>((*key >> 8) & 0xFF);
        std::uint32_t key2 = static_cast<std::uint32_t>((*key >> 16) & 0xFF);
        std::uint32_t key3 = static_cast<std::uint32_t>((*key >> 24) & 0xFF);
        std::uint32_t byte0 = value & 0xFF;
        std::uint32_t byte1 = (value >> 8) & 0xFF;
        std::uint32_t byte2 = (value >> 16) & 0xFF;
        std::uint32_t byte3 = (value >> 24) & 0xFF;
        std::uint32_t low16 = value & 0xFFFF;
        std::uint32_t keyLow = static_cast<std::uint32_t>(*key & 0xFFFF);
        std::uint32_t result = 0;

        bool done = false;
        if (near2) {
            bool borrow = low16 < keyLow;
            std::uint32_t sub = (low16 - keyLow) & 0xFFFF;
            std::uint32_t head = (sub >> 8) & 0xFF;
            if (head == 0x00 || head == 0xFF) {
                std::uint32_t low = (~low16) & 0xFFFF;
                std::uint32_t adjust = borrow ? 2 : 0;
                std::uint32_t middle = (byte2 - adjust) & 0xFF;
                bool underflow = byte2 < adjust;
                std::uint32_t sum3 = (byte3 - key3 - (underflow ? 1 : 0)) & 0xFF;
                std::uint32_t top = oddByte(sum3) ? 0xFF : 0x00;
                result = (top << 24) | (middle << 16) | low;
                done = true;
            }
        }

        if (!done && at3 && at4) {
            std::uint32_t probe = (byte0 - key0) & 0xFF;
            if (probe == 0x00 || probe == 0xFF) {
                bool borrow0 = byte0 < key0;
                std::uint32_t first = (~byte0) & 0xFF;
                std::uint32_t extra = (borrow0 ? 1 : 0);
                if (genuineAt(at - 3) && genuineAt(at - 4)) {
                    extra += 2;
                }
                std::uint32_t second = (byte1 - key1 - (borrow0 ? 1 : 0) - extra) & 0xFF;
                bool borrow1 = byte1 < key1 + (borrow0 ? 1 : 0);
                std::uint32_t third = (byte2 - key2 - (borrow1 ? 1 : 0)) & 0xFF;
                result = (byte3 << 24) | (third << 16) | (second << 8) | first;
                done = true;
            }
        }

        if (!done && near1 && at4) {
            bool borrow = low16 < keyLow;
            if (borrow && byte2 == 0x01) {
                std::uint32_t low = (~low16) & 0xFFFF;
                result = (byte3 << 24) | ((~byte2 & 0xFF) << 16) | low;
                done = true;
            }
        }

        if (!done) {
            bool borrow0 = byte0 < key0;
            std::uint32_t out0 = (byte0 - key0) & 0xFF;
            bool borrow1 = byte1 < key1 + (borrow0 ? 1 : 0);
            std::uint32_t out1 = (byte1 - key1 - (borrow0 ? 1 : 0)) & 0xFF;
            bool borrow2 = byte2 < key2 + (borrow1 ? 1 : 0);
            std::uint32_t out2 = (byte2 - key2 - (borrow1 ? 1 : 0)) & 0xFF;
            std::uint32_t sum3 = (byte3 - key3 - (borrow2 ? 1 : 0)) & 0xFF;
            std::uint32_t out3 = oddByte(sum3) ? 0xFF : 0x00;
            result = (out3 << 24) | (out2 << 16) | (out1 << 8) | out0;
            done = true;
        }

        static_cast<void>(done);
        storeDisp(std::span(pending_).subspan(scan_ + 1, dispBytes), result);
        scan_ += opcodeWindow;
    }

    std::size_t settled = scan_ < pending_.size() ? scan_ : pending_.size();
    std::size_t take = std::min({settled, output.size(), pending_.size()});
    std::copy_n(pending_.begin(), static_cast<std::ptrdiff_t>(take), output.begin());
    pending_.erase(pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(take));
    scan_ -= take;
    position_ += take;
    return Step{.consumed = input.size(), .produced = take};
}

Result<std::size_t> BcjFilter::flush(std::span<std::byte> output) {
    if (scan_ > pending_.size()) {
        return fail(ErrorKind::Malformed, "7z BCJ filter is in an invalid state");
    }
    std::size_t take = std::min(pending_.size(), output.size());
    std::copy_n(pending_.begin(), static_cast<std::ptrdiff_t>(take), output.begin());
    pending_.erase(pending_.begin(), pending_.begin() + static_cast<std::ptrdiff_t>(take));
    scan_ = 0;
    position_ += take;
    return take;
}

}
