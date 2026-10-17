#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bale {

// SECURITY: slots are placed by a randomly keyed SipHash so hostile names cannot force long probe
// chains.
class CaseFoldSet {
  public:
    CaseFoldSet();

    [[nodiscard]] std::optional<std::uint64_t>
    insertOrFindCollision(std::string_view path, std::uint64_t id);

    [[nodiscard]] std::size_t size() const {
        return size_;
    }

    void clear();

  private:
    static constexpr std::size_t emptySlot = std::numeric_limits<std::size_t>::max();

    struct Slot {
        std::uint64_t hash = 0;
        std::uint64_t id = 0;
        std::size_t offset = emptySlot;
        std::size_t length = 0;
    };

    void grow();

    std::uint64_t key0_ = 0;
    std::uint64_t key1_ = 0;
    std::string arena_;
    std::vector<Slot> slots_;
    std::size_t size_ = 0;
};

}
