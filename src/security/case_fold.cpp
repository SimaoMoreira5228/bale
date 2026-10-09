#include "security/case_fold.hpp"

#include "base/endian.hpp"
#include "security/unicode_table.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <random>

namespace bale {

namespace {

constexpr std::size_t minimumSlots = 64;
constexpr std::size_t insertionSortLimit = 32;
constexpr char32_t invalidByteBase = 0x110000;

constexpr char32_t hangulBase = 0xAC00;
constexpr char32_t hangulCount = 11172;
constexpr char32_t hangulLeadingBase = 0x1100;
constexpr char32_t hangulVowelBase = 0x1161;
constexpr char32_t hangulTrailingBase = 0x11A7;
constexpr char32_t hangulTrailingCount = 28;
constexpr char32_t hangulBlockCount = 588;

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

struct Decoded {
    char32_t codePoint = 0;
    std::size_t length = 1;
};

[[nodiscard]] Decoded decodeUtf8(std::string_view text) {
    const auto lead = static_cast<unsigned char>(text[0]);
    const Decoded invalid{
        .codePoint = invalidByteBase + lead,
        .length = 1,
    };

    std::size_t length = 0;
    char32_t value = 0;
    char32_t minimum = 0;
    if (lead < 0x80) {
        return {
            .codePoint = lead,
            .length = 1,
        };
    }
    if (lead >= 0xC2 && lead < 0xE0) {
        length = 2;
        value = lead & 0x1FU;
        minimum = 0x80;
    } else if (lead >= 0xE0 && lead < 0xF0) {
        length = 3;
        value = lead & 0x0FU;
        minimum = 0x800;
    } else if (lead >= 0xF0 && lead < 0xF5) {
        length = 4;
        value = lead & 0x07U;
        minimum = 0x10000;
    } else {
        return invalid;
    }

    if (text.size() < length) {
        return invalid;
    }
    for (std::size_t index = 1; index < length; ++index) {
        auto byte = static_cast<unsigned char>(text[index]);
        if ((byte & 0xC0U) != 0x80) {
            return invalid;
        }
        value = (value << 6) | (byte & 0x3FU);
    }

    if (value < minimum || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) {
        return invalid;
    }
    return {
        .codePoint = value,
        .length = length,
    };
}

void appendUtf8(std::string& out, char32_t codePoint) {
    if (codePoint >= invalidByteBase) {
        out.push_back(static_cast<char>(codePoint - invalidByteBase));
        return;
    }

    if (codePoint < 0x80) {
        out.push_back(static_cast<char>(codePoint));
        return;
    }
    if (codePoint < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (codePoint >> 6)));
        out.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        return;
    }
    if (codePoint < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (codePoint >> 12)));
        out.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
        return;
    }
    out.push_back(static_cast<char>(0xF0 | (codePoint >> 18)));
    out.push_back(static_cast<char>(0x80 | ((codePoint >> 12) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | ((codePoint >> 6) & 0x3F)));
    out.push_back(static_cast<char>(0x80 | (codePoint & 0x3F)));
}

void appendDecomposed(std::vector<char32_t>& out, char32_t codePoint) {
    if (codePoint >= hangulBase && codePoint < hangulBase + hangulCount) {
        const char32_t index = codePoint - hangulBase;
        out.push_back(hangulLeadingBase + index / hangulBlockCount);
        out.push_back(hangulVowelBase + index % hangulBlockCount / hangulTrailingCount);
        if (index % hangulTrailingCount != 0) {
            out.push_back(hangulTrailingBase + index % hangulTrailingCount);
        }
        return;
    }

    auto decomposition = codePointProperties(codePoint).decomposition;
    if (decomposition.empty()) {
        out.push_back(codePoint);
        return;
    }
    out.insert(out.end(), decomposition.begin(), decomposition.end());
}

[[nodiscard]] std::uint8_t combiningClass(char32_t codePoint) {
    return codePointProperties(codePoint).combiningClass;
}

void sortCombiningRun(std::vector<char32_t>& buffer, std::size_t begin, std::size_t end) {
    if (end - begin <= insertionSortLimit) {
        for (std::size_t index = begin + 1; index < end; ++index) {
            const char32_t moving = buffer[index];
            const std::uint8_t movingClass = combiningClass(moving);
            std::size_t target = index;
            while (target > begin && combiningClass(buffer[target - 1]) > movingClass) {
                buffer[target] = buffer[target - 1];
                --target;
            }
            buffer[target] = moving;
        }
        return;
    }

    // SECURITY: a hostile name can stack thousands of combining marks, so long runs use a stable
    // counting sort instead of a quadratic one.
    std::array<std::size_t, 257> starts{};
    for (std::size_t index = begin; index < end; ++index) {
        ++starts[combiningClass(buffer[index]) + 1U];
    }
    for (std::size_t value = 1; value < starts.size(); ++value) {
        starts[value] += starts[value - 1];
    }

    const std::size_t sorted = buffer.size();
    buffer.resize(sorted + (end - begin));
    for (std::size_t index = begin; index < end; ++index) {
        buffer[sorted + starts[combiningClass(buffer[index])]++] = buffer[index];
    }
    std::copy(
        buffer.begin() + static_cast<std::ptrdiff_t>(sorted),
        buffer.end(),
        buffer.begin() + static_cast<std::ptrdiff_t>(begin)
    );
    buffer.resize(sorted);
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
    appendFolded(path);

    std::string_view folded(arena_.data() + offset, arena_.size() - offset);
    const std::uint64_t hash = sipHash24(key0_, key1_, folded);
    const std::size_t mask = slots_.size() - 1;

    for (std::size_t index = hash & mask;; index = (index + 1) & mask) {
        Slot& slot = slots_[index];
        if (slot.offset == emptySlot) {
            slot.hash = hash;
            slot.id = id;
            slot.offset = offset;
            slot.length = folded.size();
            ++size_;
            return std::nullopt;
        }

        if (slot.hash == hash && slot.length == folded.size() &&
            std::string_view(arena_.data() + slot.offset, slot.length) == folded) {
            arena_.resize(offset);
            return slot.id;
        }
    }
}

// SECURITY: names match when canonically equivalent ignoring simple case, NFD(fold(NFD(name))), as
// on APFS and HFS+; on NTFS, which ignores only case, this refuses more than needed. Full folding
// (ß against ss, as Linux casefold directories do) is not applied. Invalid UTF-8 stays verbatim.
void CaseFoldSet::appendFolded(std::string_view path) {
    arena_.reserve(arena_.size() + path.size());

    std::size_t index = 0;
    while (index < path.size() && static_cast<unsigned char>(path[index]) < 0x80) {
        arena_.push_back(foldAscii(path[index]));
        ++index;
    }
    if (index == path.size()) {
        return;
    }

    scratch_.clear();
    while (index < path.size()) {
        Decoded decoded = decodeUtf8(path.substr(index));
        appendDecomposed(scratch_, decoded.codePoint);
        index += decoded.length;
    }

    std::size_t runStart = 0;
    for (std::size_t position = 0; position <= scratch_.size(); ++position) {
        if (position < scratch_.size() && combiningClass(scratch_[position]) != 0) {
            continue;
        }
        if (position - runStart > 1) {
            sortCombiningRun(scratch_, runStart, position);
        }
        runStart = position + 1;
    }

    for (char32_t codePoint : scratch_) {
        if (codePoint < invalidByteBase) {
            codePoint += static_cast<char32_t>(codePointProperties(codePoint).foldDelta);
        }
        appendUtf8(arena_, codePoint);
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
