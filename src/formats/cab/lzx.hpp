#pragma once

#include "base/error.hpp"
#include "formats/cab/tree.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace bale::cab {

// NOTE: clean-room LZX decoder written from the public format description in
// [MS-PATCH] (Microsoft LZX DELTA spec, whose sections 2.1 and 2.3 through 2.7
// specify the base LZX bitstream) and the cabinet framing in [MS-CAB]. CAB
// uses the base LZX form: no reference data, no chunk prefixes, match lengths
// 2..257 with no extra-length field, and E8 translation in 32 KiB frames.

class LzxDecoder {
  public:
    struct Output {
        std::size_t produced = 0;
        bool starved = false;
    };

    [[nodiscard]] static Result<LzxDecoder> create(unsigned windowBits, std::uint64_t totalOut);

    LzxDecoder(LzxDecoder&& other) noexcept = default;
    LzxDecoder& operator=(LzxDecoder&& other) noexcept = default;
    LzxDecoder(const LzxDecoder&) = delete;
    LzxDecoder& operator=(const LzxDecoder&) = delete;
    ~LzxDecoder() = default;

    [[nodiscard]] Result<void> push(std::span<const std::byte> chunk);

    [[nodiscard]] Result<Output> decode(std::span<std::byte> out);

    [[nodiscard]] Result<std::span<const std::byte>> finish();

    [[nodiscard]] std::uint64_t emitted() const {
        return emitted_;
    }

  private:
    enum class Phase : std::uint8_t {
        NeedStreamHeader,
        NeedBlockHeader,
        NeedTrees,
        InTokens,
        InRaw,
    };

    explicit LzxDecoder(unsigned windowBits);

    [[nodiscard]] bool fillBits(unsigned count);
    [[nodiscard]] std::uint32_t takeBits(unsigned count);
    [[nodiscard]] std::optional<std::uint8_t> takeByte();
    [[nodiscard]] bool alignInput();
    [[nodiscard]] bool alignFrame();
    [[nodiscard]] bool emitByte(std::uint8_t value);
    void translateFrame();

    [[nodiscard]] Result<std::optional<std::uint32_t>> decodeSymbol(Tree& tree);
    [[nodiscard]] Result<bool> readLengths();
    [[nodiscard]] Result<bool> readTrees();
    [[nodiscard]] Result<bool> readToken();
    [[nodiscard]] Result<bool> readMatch(std::uint32_t formatted);
    [[nodiscard]] Result<bool> readRaw();
    [[nodiscard]] Result<bool> advance();

    // NOTE: fields stay sorted by size (largest first) to avoid padding the
    // decoder; the padding lint enforces it.
    std::uint64_t totalOut_ = 0;
    std::uint64_t emitted_ = 0;
    std::size_t stashPos_ = 0;
    std::uint64_t cache_ = 0;
    std::size_t pendingPos_ = 0;
    std::size_t preIndex_ = 0;
    std::size_t alignedIndex_ = 0;
    std::size_t lenIndex_ = 0;
    std::vector<std::uint32_t> slotBase_;
    std::vector<unsigned> slotFooter_;
    std::vector<std::byte> window_;
    std::vector<std::byte> stash_;
    std::vector<std::byte> frame_;
    std::vector<std::byte> pending_;
    std::vector<std::uint8_t> prevMain_;
    std::vector<std::uint8_t> prevLength_;
    Tree mainTree_;
    Tree lengthTree_;
    Tree alignedTree_;
    Tree pretree_;

    unsigned windowBits_ = 15;
    std::uint32_t windowSize_ = 0;
    std::uint32_t numSlots_ = 0;
    unsigned bitsLeft_ = 0;
    std::uint32_t e8FileSize_ = 0;
    unsigned blockType_ = 0;
    unsigned blockSizeBytes_ = 0;
    std::uint32_t blockSize_ = 0;
    std::uint32_t blockLeft_ = 0;
    unsigned treeStage_ = 0;
    unsigned treeTarget_ = 0;
    std::uint32_t lenLeft_ = 0;
    std::uint32_t lenValue_ = 0;
    std::uint32_t lenCode_ = 0;
    std::uint32_t lenSame_ = 0;
    std::uint32_t symCode_ = 0;
    unsigned symLen_ = 0;
    unsigned tokStage_ = 0;
    std::uint32_t tokHeader_ = 0;
    std::uint32_t tokSlot_ = 0;
    std::uint32_t tokLength_ = 0;
    std::uint32_t tokVerbatim_ = 0;
    std::uint32_t rawLeft_ = 0;
    unsigned rawNeed_ = 0;
    std::uint32_t repeat_[3] = {1, 1, 1};

    bool atEnd_ = false;
    bool padPending_ = false;
    Phase phase_ = Phase::NeedStreamHeader;
    bool flagRead_ = false;
    bool e8Enabled_ = false;
    bool e8SizeRead_ = false;
    bool typeRead_ = false;
    bool lenNeedCode_ = false;
    bool lenCodeRead_ = false;
    bool symActive_ = false;
    bool rawPad_ = false;
    bool rawRepeatRead_ = false;
    bool finished_ = false;
    std::uint8_t rawRepeat_[12] = {};
};

}
