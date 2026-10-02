#include "security/case_fold.hpp"

#include "base/endian.hpp"

#include <bit>
#include <random>

namespace bale {

namespace {

constexpr std::size_t minimumSlots = 64;

[[nodiscard]] std::uint64_t
sipHash24(std::uint64_t key0, std::uint64_t key1, std::string_view text) {
    std::uint64_t v0 = 0x736f6d6570736575 ^ key0;
    std::uint64_t v1 = 0x646f72616e646f6d ^ key1;
    std::uint64_t v2 = 0x6c7967656e657261 ^ key0;
    std::uint64_t v3 = 0x7465646279746573 ^ key1;

    auto round = [&] {
        v0 += v1;
        v1 = std::rotl(v1, 13);
        v1 ^= v0;
        v0 = std::rotl(v0, 32);
        v2 += v3;
        v3 = std::rotl(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = std::rotl(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = std::rotl(v1, 17);
        v1 ^= v2;
        v2 = std::rotl(v2, 32);
    };

    const auto* bytes = reinterpret_cast<const std::byte*>(text.data());
    const std::size_t whole = text.size() & ~std::size_t{7};
    for (std::size_t i = 0; i < whole; i += 8) {
        auto word = loadLe<std::uint64_t>(bytes + i);
        v3 ^= word;
        round();
        round();
        v0 ^= word;
    }

    std::uint64_t last = static_cast<std::uint64_t>(text.size()) << 56;
    for (std::size_t i = whole; i < text.size(); ++i) {
        last |= static_cast<std::uint64_t>(static_cast<unsigned char>(text[i]))
            << (8 * (i - whole));
    }
    v3 ^= last;
    round();
    round();
    v0 ^= last;

    v2 ^= 0xff;
    round();
    round();
    round();
    round();
    return v0 ^ v1 ^ v2 ^ v3;
}

[[nodiscard]] constexpr char foldAscii(char c) {
    if (c >= 'A' && c <= 'Z') {
        return static_cast<char>(c + ('a' - 'A'));
    }
    return c;
}

}

CaseFoldSet::CaseFoldSet() {
    std::random_device seed;
    key0_ = (static_cast<std::uint64_t>(seed()) << 32) | seed();
    key1_ = (static_cast<std::uint64_t>(seed()) << 32) | seed();
}

std::optional<std::uint64_t>
CaseFoldSet::insertOrFindCollision(std::string_view path, std::uint64_t id) {
    if ((size_ + 1) * 2 > slots_.size()) {
        grow();
    }

    const std::size_t offset = arena_.size();
    // TODO: full Unicode simple case folding (CaseFolding.txt C+S) and the NFD form macOS uses;
    // until then only ASCII letters fold, so non-ASCII case variants are not reported.
    arena_.reserve(offset + path.size());
    for (char c : path) {
        arena_.push_back(foldAscii(c));
    }

    std::string_view folded(arena_.data() + offset, path.size());
    const std::uint64_t hash = sipHash24(key0_, key1_, folded);
    const std::size_t mask = slots_.size() - 1;

    for (std::size_t index = hash & mask;; index = (index + 1) & mask) {
        Slot& slot = slots_[index];
        if (slot.offset == emptySlot) {
            slot.hash = hash;
            slot.id = id;
            slot.offset = offset;
            slot.length = path.size();
            ++size_;
            return std::nullopt;
        }

        if (slot.hash == hash && slot.length == path.size() &&
            std::string_view(arena_.data() + slot.offset, slot.length) == folded) {
            arena_.resize(offset);
            return slot.id;
        }
    }
}

void CaseFoldSet::clear() {
    arena_.clear();
    slots_.clear();
    size_ = 0;
}

void CaseFoldSet::grow() {
    std::vector<Slot> old = std::move(slots_);
    slots_.assign(old.empty() ? minimumSlots : old.size() * 2, Slot{});

    const std::size_t mask = slots_.size() - 1;
    for (const Slot& slot : old) {
        if (slot.offset == emptySlot) {
            continue;
        }

        std::size_t index = slot.hash & mask;
        while (slots_[index].offset != emptySlot) {
            index = (index + 1) & mask;
        }
        slots_[index] = slot;
    }
}

}
