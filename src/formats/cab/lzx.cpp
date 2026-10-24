#include "formats/cab/lzx.hpp"

#include "base/endian.hpp"

#include <cstring>
#include <string_view>

namespace bale::cab {

namespace {

constexpr std::size_t maxStashBytes = std::size_t{1} << 20;
constexpr std::size_t e8FrameBytes = 32768;
constexpr std::size_t e8TailBytes = 10;
constexpr std::uint64_t e8CutoffOffset = std::uint64_t{1} << 30;
constexpr std::size_t lengthSymbols = 249;
constexpr std::size_t pretreeSymbols = 20;
constexpr std::size_t alignedSymbols = 8;
constexpr std::uint32_t wimDefaultBlockSize = 32768;

[[nodiscard]] std::string_view overrunWhat(LzxFraming framing) {
    if (framing == LzxFraming::Wim) {
        return "WIM LZX chunk exceeds its declared size";
    }
    return "LZX stream exceeds its cabinet folder";
}

}

Result<LzxDecoder>
LzxDecoder::create(unsigned windowBits, std::uint64_t totalOut, LzxFraming framing) {
    if (windowBits < 15 || windowBits > 21) {
        if (framing == LzxFraming::Wim) {
            return fail(ErrorKind::Unsupported, "WIM LZX window is not supported");
        }
        return fail(ErrorKind::Unsupported, "cabinet LZX window is not supported");
    }
    LzxDecoder decoder(windowBits, framing);
    decoder.totalOut_ = totalOut;
    decoder.atEnd_ = totalOut == 0;
    return decoder;
}

LzxDecoder::LzxDecoder(unsigned windowBits, LzxFraming framing) :
    windowBits_(windowBits), framing_(framing) {
    windowSize_ = std::uint32_t{1} << windowBits_;
    switch (windowBits_) {
    case 15:
        numSlots_ = 30;
        break;
    case 16:
        numSlots_ = 32;
        break;
    case 17:
        numSlots_ = 34;
        break;
    case 18:
        numSlots_ = 36;
        break;
    case 19:
        numSlots_ = 38;
        break;
    case 20:
        numSlots_ = 42;
        break;
    default:
        numSlots_ = 50;
        break;
    }

    slotBase_.resize(numSlots_);
    slotFooter_.resize(numSlots_);
    slotBase_[0] = 0;
    slotBase_[1] = 1;
    slotBase_[2] = 2;
    slotFooter_[0] = 0;
    slotFooter_[1] = 0;
    slotFooter_[2] = 0;
    if (numSlots_ > 3) {
        slotBase_[3] = 3;
        slotFooter_[3] = 0;
    }
    for (std::uint32_t slot = 4; slot < numSlots_ && slot <= 37; ++slot) {
        unsigned half = slot >> 1;
        if ((slot & 1) == 0) {
            slotBase_[slot] = std::uint32_t{1} << half;
        } else {
            slotBase_[slot] = (std::uint32_t{1} << half) + (std::uint32_t{1} << (half - 1));
        }
        slotFooter_[slot] = half - 1;
    }
    for (std::uint32_t slot = 38; slot < numSlots_; ++slot) {
        slotBase_[slot] = 262144 + (slot - 36) * 131072;
        slotFooter_[slot] = 17;
    }

    window_.resize(windowSize_);
    prevMain_.assign(256 + std::size_t{8} * numSlots_, 0);
    prevLength_.assign(lengthSymbols, 0);
}

Result<void> LzxDecoder::push(std::span<const std::byte> chunk) {
    if (finished_) {
        return fail(ErrorKind::Malformed, "LZX decoder already finished");
    }
    if (stash_.size() - stashPos_ + chunk.size() > maxStashBytes) {
        return fail(ErrorKind::LimitExceeded, "LZX input exceeds buffer limit");
    }
    stash_.insert(stash_.end(), chunk.begin(), chunk.end());
    return {};
}

Result<std::span<const std::byte>> LzxDecoder::finish() {
    if (finished_) {
        return std::span<const std::byte>(
            pending_.data() + pendingPos_,
            pending_.size() - pendingPos_
        );
    }
    if (blockLeft_ != 0) {
        if (framing_ == LzxFraming::Wim) {
            return fail(ErrorKind::Malformed, "WIM LZX chunk ends inside a block");
        }
        return fail(ErrorKind::Malformed, "cabinet folder ends inside an LZX block");
    }
    if (phase_ == Phase::InTokens || phase_ == Phase::InRaw) {
        phase_ = Phase::NeedBlockHeader;
    }
    if (!frame_.empty()) {
        translateFrame();
        pending_.insert(pending_.end(), frame_.begin(), frame_.end());
        frame_.clear();
    }
    finished_ = true;
    return std::span<const std::byte>(pending_.data() + pendingPos_, pending_.size() - pendingPos_);
}

bool LzxDecoder::fillBits(unsigned count) {
    while (bitsLeft_ < count) {
        if (stashPos_ + 2 > stash_.size()) {
            return false;
        }
        std::uint16_t word = loadLe<std::uint16_t>(stash_.data() + stashPos_);
        stashPos_ += 2;
        std::uint64_t kept = bitsLeft_ == 0 ? 0 : cache_ & ((std::uint64_t{1} << bitsLeft_) - 1);
        cache_ = (kept << 16) | word;
        bitsLeft_ += 16;
    }
    return true;
}

std::uint32_t LzxDecoder::takeBits(unsigned count) {
    bitsLeft_ -= count;
    return static_cast<std::uint32_t>((cache_ >> bitsLeft_) & ((std::uint64_t{1} << count) - 1));
}

std::optional<std::uint8_t> LzxDecoder::takeByte() {
    if (padPending_ && !alignFrame()) {
        return std::nullopt;
    }
    if (bitsLeft_ >= 8) {
        return static_cast<std::uint8_t>(takeBits(8));
    }
    if (bitsLeft_ != 0) {
        return std::nullopt;
    }
    if (stashPos_ >= stash_.size()) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(stash_[stashPos_++]);
}

bool LzxDecoder::alignInput() {
    unsigned drop = bitsLeft_ % 16;
    if (drop == 0) {
        drop = 16;
    }
    if (!fillBits(drop)) {
        return false;
    }
    static_cast<void>(takeBits(drop));
    return true;
}

bool LzxDecoder::alignFrame() {
    unsigned drop = bitsLeft_ % 16;
    if (drop > 0 && !fillBits(drop)) {
        return false;
    }
    if (drop > 0) {
        static_cast<void>(takeBits(drop));
    }
    padPending_ = false;
    return true;
}

bool LzxDecoder::emitByte(std::uint8_t value) {
    if (emitted_ >= totalOut_) {
        return false;
    }
    window_[emitted_ % windowSize_] = static_cast<std::byte>(value);
    ++emitted_;
    --blockLeft_;
    if (emitted_ == totalOut_) {
        atEnd_ = true;
    }
    // NOTE: the 32 KiB frame padding below is CAB framing; WIM chunks have
    // no alignment padding, so the flag must stay clear in WIM mode.
    if (framing_ == LzxFraming::Cab && emitted_ != 0 && emitted_ % e8FrameBytes == 0) {
        padPending_ = true;
    }
    if (e8Enabled_) {
        frame_.push_back(static_cast<std::byte>(value));
        if (frame_.size() == e8FrameBytes) {
            translateFrame();
            pending_.insert(pending_.end(), frame_.begin(), frame_.end());
            frame_.clear();
        }
        return true;
    }
    pending_.push_back(static_cast<std::byte>(value));
    return true;
}

void LzxDecoder::translateFrame() {
    auto chunkOffset = static_cast<std::int64_t>(emitted_ - frame_.size());
    if (frame_.size() <= e8TailBytes || chunkOffset >= static_cast<std::int64_t>(e8CutoffOffset)) {
        return;
    }

    std::size_t index = 0;
    // NOTE: no E8 translation in the last bytes of a frame; matches MS-PATCH.
    std::size_t bound = frame_.size() - e8TailBytes;
    auto fileSize = static_cast<std::int64_t>(e8FileSize_);
    while (index < bound) {
        if (frame_[index] != std::byte{0xE8}) {
            ++index;
            continue;
        }
        std::int32_t value =
            static_cast<std::int32_t>(loadLe<std::uint32_t>(frame_.data() + index + 1));
        std::int64_t current = chunkOffset + static_cast<std::int64_t>(index);
        if (static_cast<std::int64_t>(value) >= -current &&
            static_cast<std::int64_t>(value) < fileSize) {
            std::int64_t target = value >= 0 ? static_cast<std::int64_t>(value) - current
                                             : static_cast<std::int64_t>(value) + fileSize;
            storeLe(frame_.data() + index + 1, static_cast<std::uint32_t>(target));
        }
        index += 5;
    }
}

Result<std::optional<std::uint32_t>> LzxDecoder::decodeSymbol(Tree& tree) {
    if (!symActive_) {
        symCode_ = 0;
        symLen_ = 0;
        symActive_ = true;
    }

    while (symLen_ < maxCodeBits) {
        if (!fillBits(1)) {
            return std::optional<std::uint32_t>{};
        }
        symCode_ = (symCode_ << 1) | takeBits(1);
        ++symLen_;
        if (symLen_ > maxCodeBits || symLen_ == 0) {
            return fail(ErrorKind::Malformed, "LZX Huffman code is invalid");
        }
        if (symCode_ >= tree.firstCode[symLen_]) {
            std::uint32_t index = symCode_ - tree.firstCode[symLen_];
            if (index < tree.counts[symLen_]) {
                symActive_ = false;
                return tree.symbols[tree.firstSymbol[symLen_] + index];
            }
        }
    }
    return fail(ErrorKind::Malformed, "LZX Huffman code is invalid");
}

Result<bool> LzxDecoder::readLengths() {
    std::vector<std::uint8_t>* target = nullptr;
    const std::vector<std::uint8_t>* prev = nullptr;
    std::size_t count = 0;
    Tree* tree = nullptr;
    if (treeTarget_ == 0) {
        target = &mainTree_.lengths;
        prev = &prevMain_;
        count = 256;
        tree = &mainTree_;
    } else if (treeTarget_ == 1) {
        target = &mainTree_.lengths;
        prev = &prevMain_;
        count = 256 + std::size_t{8} * numSlots_;
        tree = &mainTree_;
    } else {
        target = &lengthTree_.lengths;
        prev = &prevLength_;
        count = lengthSymbols;
        tree = &lengthTree_;
    }
    // NOTE: lengths persist across starved (partial-input) resumes, so only
    // clear them when the section has not started yet (any progress marker
    // set means entries were already stored and must be kept).
    if (treeTarget_ == 0) {
        if (lenIndex_ == 0 && lenLeft_ == 0 && !lenNeedCode_) {
            target->assign(256 + std::size_t{8} * numSlots_, 0);
        }
    } else if (treeTarget_ == 2) {
        if (lenIndex_ == 0 && lenLeft_ == 0 && !lenNeedCode_) {
            target->assign(lengthSymbols, 0);
        }
    }

    while (lenIndex_ < count) {
        if (lenLeft_ > 0) {
            (*target)[lenIndex_] = static_cast<std::uint8_t>(lenValue_);
            ++lenIndex_;
            --lenLeft_;
            continue;
        }
        if (lenNeedCode_) {
            auto second = decodeSymbol(pretree_);
            if (!second) {
                return tl::unexpected<Error>(second.error());
            }
            if (!*second) {
                return false;
            }
            std::uint32_t code = second->value_or(0);
            if (code > maxCodeBits) {
                return fail(ErrorKind::Malformed, "LZX tree code is out of range");
            }
            std::uint32_t base = (*prev)[lenIndex_];
            lenValue_ = (base - code + 17) % 17;
            lenLeft_ = lenSame_;
            lenNeedCode_ = false;
            continue;
        }

        std::uint32_t value;
        if (!lenCodeRead_) {
            auto code = decodeSymbol(pretree_);
            if (!code) {
                return tl::unexpected<Error>(code.error());
            }
            if (!*code) {
                return false;
            }
            // NOTE: the decoded tree code must survive starved (partial-input)
            // resumes below: the fillBits calls can need more input, and the
            // local `value` would otherwise be lost and the raw bits decoded
            // as a fresh code on resume.
            lenCode_ = code->value_or(0);
            lenCodeRead_ = true;
        }
        value = lenCode_;
        if (value <= maxCodeBits) {
            std::uint32_t base = (*prev)[lenIndex_];
            (*target)[lenIndex_] = static_cast<std::uint8_t>((base - value + 17) % 17);
            ++lenIndex_;
            lenCodeRead_ = false;
        } else if (value == 17) {
            if (!fillBits(4)) {
                return false;
            }
            lenValue_ = 0;
            lenLeft_ = 4 + takeBits(4);
            lenCodeRead_ = false;
        } else if (value == 18) {
            if (!fillBits(5)) {
                return false;
            }
            lenValue_ = 0;
            lenLeft_ = 20 + takeBits(5);
            lenCodeRead_ = false;
        } else {
            if (!fillBits(1)) {
                return false;
            }
            lenSame_ = 4 + takeBits(1);
            lenNeedCode_ = true;
            lenCodeRead_ = false;
        }
    }

    auto built = buildTree(*tree, count);
    if (!built) {
        return tl::unexpected<Error>(built.error());
    }
    if (treeTarget_ == 1) {
        prevMain_ = mainTree_.lengths;
    } else if (treeTarget_ == 2) {
        prevLength_ = lengthTree_.lengths;
    }
    return true;
}

Result<bool> LzxDecoder::readTrees() {
    if (treeStage_ == 0) {
        if (blockType_ != 2) {
            treeStage_ = 1;
            treeTarget_ = 0;
            preIndex_ = 0;
        } else {
            // NOTE: lengths persist across starved (partial-input) resumes,
            // so only clear them when no element has been stored yet.
            if (alignedIndex_ == 0) {
                alignedTree_.lengths.assign(alignedSymbols, 0);
            }
            while (alignedIndex_ < alignedSymbols) {
                if (!fillBits(3)) {
                    return false;
                }
                alignedTree_.lengths[alignedIndex_] = static_cast<std::uint8_t>(takeBits(3));
                ++alignedIndex_;
            }
            auto built = buildTree(alignedTree_, alignedSymbols);
            if (!built) {
                return tl::unexpected<Error>(built.error());
            }
            treeStage_ = 1;
            treeTarget_ = 0;
            preIndex_ = 0;
        }
        return true;
    }

    if (treeStage_ == 1) {
        // NOTE: see above: keep already-stored lengths on resume.
        if (preIndex_ == 0) {
            pretree_.lengths.assign(pretreeSymbols, 0);
        }
        while (preIndex_ < pretreeSymbols) {
            if (!fillBits(4)) {
                return false;
            }
            pretree_.lengths[preIndex_] = static_cast<std::uint8_t>(takeBits(4));
            ++preIndex_;
        }
        auto built = buildTree(pretree_, pretreeSymbols);
        if (!built) {
            return tl::unexpected<Error>(built.error());
        }
        treeStage_ = 2;
        lenIndex_ = treeTarget_ == 1 ? 256 : 0;
        lenLeft_ = 0;
        lenNeedCode_ = false;
        return true;
    }

    auto done = readLengths();
    if (!done) {
        return tl::unexpected<Error>(done.error());
    }
    if (!*done) {
        return false;
    }

    ++treeTarget_;
    if (treeTarget_ >= 3) {
        phase_ = Phase::InTokens;
        tokStage_ = 0;
        return true;
    }
    treeStage_ = 1;
    preIndex_ = 0;
    return true;
}

Result<bool> LzxDecoder::readToken() {
    if (tokStage_ == 0) {
        auto symbol = decodeSymbol(mainTree_);
        if (!symbol) {
            return tl::unexpected<Error>(symbol.error());
        }
        if (!*symbol) {
            return false;
        }

        std::uint32_t element = symbol->value_or(0);
        if (element < 256) {
            if (!emitByte(static_cast<std::uint8_t>(element))) {
                return fail(ErrorKind::Malformed, overrunWhat(framing_));
            }
            return true;
        }

        std::uint32_t lenPos = element - 256;
        tokHeader_ = lenPos & 7;
        tokSlot_ = lenPos >> 3;
        if (tokSlot_ >= numSlots_) {
            return fail(ErrorKind::Malformed, "LZX match slot is out of range");
        }
        tokStage_ = tokHeader_ == 7 ? 1 : 2;
        return true;
    }

    if (tokStage_ == 1) {
        auto symbol = decodeSymbol(lengthTree_);
        if (!symbol) {
            return tl::unexpected<Error>(symbol.error());
        }
        if (!*symbol) {
            return false;
        }
        tokLength_ = symbol->value_or(0) + 9;
        tokStage_ = 2;
        return true;
    }

    if (tokStage_ == 2) {
        unsigned footer = slotFooter_[tokSlot_];
        unsigned verbatim = footer;
        // NOTE: per [MS-PATCH] 2.6.3, the footer splits into verbatim +
        // aligned bits whenever the formatted offset can exceed 15, i.e.
        // for every slot with at least 3 footer bits (slots 8+); only
        // slots 0..7 (formatted offset <= 15) stay verbatim-only.
        if (blockType_ == 2 && footer >= 3) {
            verbatim = footer - 3;
        }
        if (verbatim > 0) {
            if (!fillBits(verbatim)) {
                return false;
            }
            tokVerbatim_ = takeBits(verbatim);
        } else {
            tokVerbatim_ = 0;
        }
        if (blockType_ == 2 && footer >= 3) {
            tokStage_ = 3;
        } else {
            tokLength_ = tokHeader_ == 7 ? tokLength_ : tokHeader_ + 2;
            std::uint32_t formatted = slotBase_[tokSlot_] + tokVerbatim_;
            return readMatch(formatted);
        }
        return true;
    }

    auto symbol = decodeSymbol(alignedTree_);
    if (!symbol) {
        return tl::unexpected<Error>(symbol.error());
    }
    if (!*symbol) {
        return false;
    }

    tokLength_ = tokHeader_ == 7 ? tokLength_ : tokHeader_ + 2;
    std::uint32_t formatted = slotBase_[tokSlot_] + (tokVerbatim_ << 3) + symbol->value_or(0);
    return readMatch(formatted);
}

Result<bool> LzxDecoder::readMatch(std::uint32_t formatted) {
    std::uint32_t match = 0;
    if (tokSlot_ == 0) {
        match = repeat_[0];
    } else if (tokSlot_ == 1) {
        match = repeat_[1];
        repeat_[1] = repeat_[0];
        repeat_[0] = match;
    } else if (tokSlot_ == 2) {
        match = repeat_[2];
        repeat_[2] = repeat_[0];
        repeat_[0] = match;
    } else {
        if (formatted < 2) {
            return fail(ErrorKind::Malformed, "LZX match offset is out of range");
        }
        match = formatted - 2;
        repeat_[2] = repeat_[1];
        repeat_[1] = repeat_[0];
        repeat_[0] = match;
    }

    if (match == 0 || match > windowSize_ || match > emitted_) {
        return fail(ErrorKind::Malformed, "LZX match offset is out of range");
    }

    for (std::uint32_t index = 0; index < tokLength_; ++index) {
        std::uint64_t from = emitted_ - match;
        if (!emitByte(static_cast<std::uint8_t>(window_[from % windowSize_]))) {
            return fail(ErrorKind::Malformed, overrunWhat(framing_));
        }
    }
    tokStage_ = 0;
    return true;
}

Result<bool> LzxDecoder::readRaw() {
    while (rawNeed_ > 0) {
        auto byte = takeByte();
        if (!byte) {
            return false;
        }
        rawRepeat_[12 - rawNeed_] = *byte;
        --rawNeed_;
    }
    if (!rawRepeatRead_) {
        rawRepeatRead_ = true;
        std::uint32_t loaded[3];
        for (unsigned index = 0; index < 3; ++index) {
            const auto* word = reinterpret_cast<const std::byte*>(
                rawRepeat_ + static_cast<std::size_t>(index) * 4
            );
            loaded[index] = loadLe<std::uint32_t>(word);
            if (loaded[index] == 0 || loaded[index] > windowSize_) {
                return fail(ErrorKind::Malformed, "LZX repeated offset is out of range");
            }
        }
        repeat_[0] = loaded[0];
        repeat_[1] = loaded[1];
        repeat_[2] = loaded[2];
    }

    while (rawLeft_ > 0) {
        auto byte = takeByte();
        if (!byte) {
            return false;
        }
        if (!emitByte(*byte)) {
            return fail(ErrorKind::Malformed, overrunWhat(framing_));
        }
        --rawLeft_;
    }

    if (rawPad_) {
        auto pad = takeByte();
        if (!pad) {
            return false;
        }
        rawPad_ = false;
    }

    phase_ = Phase::NeedBlockHeader;
    return true;
}

Result<bool> LzxDecoder::advance() {
    if (padPending_ && !alignFrame()) {
        return false;
    }
    switch (phase_) {
    case Phase::NeedStreamHeader: {
        if (framing_ == LzxFraming::Wim) {
            // NOTE: WIM chunks carry no stream header; the fixed E8 pass
            // runs per chunk outside the core, so raw bytes land in pending_.
            phase_ = Phase::NeedBlockHeader;
            return true;
        }
        if (!flagRead_) {
            if (!fillBits(1)) {
                return false;
            }
            e8Enabled_ = takeBits(1) != 0;
            flagRead_ = true;
        }
        if (e8Enabled_ && !e8SizeRead_) {
            if (!fillBits(32)) {
                return false;
            }
            std::uint32_t high = takeBits(16);
            std::uint32_t low = takeBits(16);
            e8FileSize_ = (high << 16) | low;
            e8SizeRead_ = true;
        }
        phase_ = Phase::NeedBlockHeader;
        return true;
    }
    case Phase::NeedBlockHeader: {
        if (!typeRead_) {
            if (!fillBits(3)) {
                return false;
            }
            blockType_ = takeBits(3);
            if (blockType_ < 1 || blockType_ > 3) {
                return fail(ErrorKind::Malformed, "LZX block type is invalid");
            }
            typeRead_ = true;
            blockSizeBytes_ = 0;
            blockSize_ = 0;
            sizeFlagRead_ = false;
            sizeIsDefault_ = false;
        }
        if (framing_ == LzxFraming::Wim) {
            if (!sizeFlagRead_) {
                if (!fillBits(1)) {
                    return false;
                }
                sizeIsDefault_ = takeBits(1) != 0;
                sizeFlagRead_ = true;
            }
            if (sizeIsDefault_) {
                blockSize_ = wimDefaultBlockSize;
            } else {
                // NOTE: 16 size bits below 64 KiB windows, 24 above; the
                // flag bit makes the field 1+16 or 1+24 bits wide.
                unsigned want = windowSize_ >= 65536 ? 3 : 2;
                while (blockSizeBytes_ < want) {
                    if (!fillBits(8)) {
                        return false;
                    }
                    blockSize_ = (blockSize_ << 8) | takeBits(8);
                    ++blockSizeBytes_;
                }
                if (blockSize_ == 0) {
                    return fail(ErrorKind::Malformed, "WIM LZX block size is invalid");
                }
            }
        } else {
            while (blockSizeBytes_ < 3) {
                if (!fillBits(8)) {
                    return false;
                }
                blockSize_ = (blockSize_ << 8) | takeBits(8);
                ++blockSizeBytes_;
            }
        }
        typeRead_ = false;
        sizeFlagRead_ = false;
        blockLeft_ = blockSize_;
        if (framing_ == LzxFraming::Wim) {
            auto room = totalOut_ >= emitted_ ? totalOut_ - emitted_ : 0;
            if (blockSize_ > room) {
                return fail(ErrorKind::Malformed, "WIM LZX block exceeds its chunk");
            }
        }
        if (blockType_ == 3) {
            if (!alignInput()) {
                return false;
            }
            rawNeed_ = 12;
            rawRepeatRead_ = false;
            rawLeft_ = blockSize_;
            rawPad_ = (blockSize_ & 1) != 0;
            phase_ = Phase::InRaw;
        } else {
            treeStage_ = 0;
            treeTarget_ = 0;
            alignedIndex_ = 0;
            phase_ = Phase::NeedTrees;
        }
        return true;
    }
    case Phase::NeedTrees:
        return readTrees();
    case Phase::InTokens: {
        if (blockLeft_ == 0) {
            phase_ = Phase::NeedBlockHeader;
            return true;
        }
        return readToken();
    }
    case Phase::InRaw:
        return readRaw();
    }
    return fail(ErrorKind::Malformed, "LZX decoder is in an invalid state");
}

Result<LzxDecoder::Output> LzxDecoder::decode(std::span<std::byte> out) {
    if (finished_) {
        return fail(ErrorKind::Malformed, "LZX decoder already finished");
    }

    Output result;
    while (result.produced < out.size()) {
        std::size_t avail = pending_.size() - pendingPos_;
        if (avail > 0) {
            std::size_t room = out.size() - result.produced;
            std::size_t take = avail < room ? avail : room;
            std::memcpy(out.data() + result.produced, pending_.data() + pendingPos_, take);
            pendingPos_ += take;
            result.produced += take;
            if (pendingPos_ == pending_.size()) {
                pending_.clear();
                pendingPos_ = 0;
            }
            continue;
        }
        // NOTE: the final bytes may complete the folder while output is still
        // buffered above; drain it before reporting the end of stream.
        if (atEnd_) {
            break;
        }

        auto stepped = advance();
        if (!stepped) {
            return tl::unexpected<Error>(stepped.error());
        }
        if (!*stepped) {
            result.starved = true;
            break;
        }
    }

    if (stashPos_ > 32768) {
        stash_.erase(stash_.begin(), stash_.begin() + static_cast<std::ptrdiff_t>(stashPos_));
        stashPos_ = 0;
    }
    return result;
}

}
