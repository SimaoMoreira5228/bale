#include "formats/sevenzip/folder.hpp"

#include "base/checked.hpp"
#include "formats/sevenzip/methods.hpp"

#include <algorithm>

namespace bale::sevenzip {

namespace {

bool idEquals(std::span<const std::uint8_t> id, std::span<const std::uint8_t> want) {
    return id.size() == want.size() && std::ranges::equal(id, want);
}

std::string codecName(std::span<const std::uint8_t> id) {
    if (idEquals(id, methodCopy)) {
        return "Copy";
    }
    if (idEquals(id, methodLzma1)) {
        return "LZMA1";
    }
    if (idEquals(id, methodLzma2)) {
        return "LZMA2";
    }
    if (idEquals(id, methodDeflate)) {
        return "Deflate";
    }
    if (idEquals(id, methodBzip2)) {
        return "BZip2";
    }
    if (idEquals(id, methodAes)) {
        return "AES-256";
    }
    if (idEquals(id, methodPpmd)) {
        return "PPMd";
    }
    if (idEquals(id, methodBcj)) {
        return "BCJ";
    }
    if (idEquals(id, methodBcj2)) {
        return "BCJ2";
    }
    if (idEquals(id, methodDelta)) {
        return "Delta";
    }
    if (idEquals(id, methodSwap2)) {
        return "Swap2";
    }
    if (idEquals(id, methodSwap4)) {
        return "Swap4";
    }
    if (idEquals(id, methodPpc)) {
        return "PPC";
    }
    if (idEquals(id, methodIa64)) {
        return "IA64";
    }
    if (idEquals(id, methodArm)) {
        return "ARM";
    }
    if (idEquals(id, methodArmThumb)) {
        return "ARMT";
    }
    if (idEquals(id, methodSparc)) {
        return "SPARC";
    }
    if (idEquals(id, methodArm64)) {
        return "ARM64";
    }
    if (idEquals(id, methodRiscv)) {
        return "RISC-V";
    }
    return "unknown";
}

std::string codecHex(std::span<const std::uint8_t> id) {
    std::string text;
    for (std::uint8_t byte : id) {
        if (!text.empty()) {
            text += '-';
        }
        constexpr char digits[] = "0123456789ABCDEF";
        text += digits[byte >> 4];
        text += digits[byte & 0x0F];
    }
    return text;
}

}

bool isMainCodec(std::span<const std::uint8_t> id, Codec& codec) {
    if (idEquals(id, methodCopy)) {
        codec = Codec::Copy;
        return true;
    }
    if (idEquals(id, methodLzma1)) {
        codec = Codec::Lzma1;
        return true;
    }
    if (idEquals(id, methodLzma2)) {
        codec = Codec::Lzma2;
        return true;
    }
    if (idEquals(id, methodDeflate)) {
        codec = Codec::Deflate;
        return true;
    }
    if (idEquals(id, methodBzip2)) {
        codec = Codec::Bzip2;
        return true;
    }
    return false;
}

CodecInfo unsupportedInfo(std::string name, std::string hex) {
    CodecInfo info;
    info.supported = false;
    info.name = std::move(name);
    info.hex = std::move(hex);
    return info;
}

CodecInfo resolveCodec(const Folder& folder) {
    for (const auto& coder : folder.coders) {
        if (idEquals(coder.id, methodAes)) {
            return CodecInfo{
                .codec = Codec::Copy,
                .props = {},
                .encrypted = true,
                .supported = true,
                .name = {},
                .hex = {},
            };
        }
        if (idEquals(coder.id, methodBcj2)) {
            CodecInfo info = unsupportedInfo(codecName(coder.id), codecHex(coder.id));
            return info;
        }
    }

    CodecInfo info;
    if (folder.coders.size() == 2) {
        const Coder& main = folder.coders[0];
        const Coder& filter = folder.coders[1];
        bool isBcj = idEquals(filter.id, methodBcj);
        bool linear = main.inStreams == 1 && main.outStreams == 1 && filter.inStreams == 1 &&
            filter.outStreams == 1;
        bool linked = folder.binds.size() == 1 && folder.binds[0].inIndex == 1 &&
            folder.binds[0].outIndex == 0;
        bool packedMain = folder.numInStreams == 2 && folder.numOutStreams == 2 &&
            folder.numPackedStreams == 1 && folder.finalOutStream == 1 &&
            (folder.packedStreams.empty() || folder.packedStreams[0] == 0);
        if (isBcj && filter.props.empty() && linear && linked && packedMain &&
            isMainCodec(main.id, info.codec)) {
            info.props.assign(main.props.begin(), main.props.end());
            info.name = codecName(main.id) + " + BCJ";
            info.hex = codecHex(main.id) + "+" + codecHex(filter.id);
            info.bcjFilter = true;
            return info;
        }

        info.supported = false;
        info.name = "filter chain";
        return info;
    }
    if (folder.coders.size() != 1) {
        info.supported = false;
        info.name = "filter chain";
        info.hex = "";
        return info;
    }

    const Coder& coder = folder.coders.front();
    if (coder.inStreams != 1 || coder.outStreams != 1 || !folder.binds.empty()) {
        info.supported = false;
        info.name = "filter chain";
        info.hex = "";
        return info;
    }

    info.props.assign(coder.props.begin(), coder.props.end());
    info.name = codecName(coder.id);
    info.hex = codecHex(coder.id);
    if (idEquals(coder.id, methodBcj)) {
        if (!coder.props.empty()) {
            info.supported = false;
            return info;
        }
        info.codec = Codec::Bcj;
        return info;
    }
    if (isMainCodec(coder.id, info.codec)) {
        return info;
    }

    info.supported = false;
    return info;
}

Result<FolderPlan> resolveFolder(
    const Folder& folder,
    const std::vector<PackStream>& packs,
    std::uint64_t firstPackStream,
    std::uint64_t packBase,
    std::uint64_t fileSize,
    const Limits& limits
) {
    FolderPlan plan;
    plan.codec = resolveCodec(folder);
    if (!plan.codec.encrypted && !plan.codec.supported) {
        std::string text;
        if (plan.codec.hex.empty()) {
            text = "7z " + plan.codec.name + "s are not supported";
        } else {
            text = "7z codec " + plan.codec.name + " (" + plan.codec.hex + ") is not supported";
        }

        plan.failureSize = std::min(text.size(), plan.failureMessage.size() - 1);
        std::copy_n(text.data(), plan.failureSize, plan.failureMessage.data());
        plan.failureMessage[plan.failureSize] = '\0';
    }

    if (folder.unpackSizes.size() != folder.numOutStreams) {
        return fail(ErrorKind::Malformed, "7z folder unpack sizes do not match", packBase);
    }
    if (folder.finalOutStream >= folder.unpackSizes.size()) {
        return fail(ErrorKind::Malformed, "7z folder final output is out of range", packBase);
    }

    for (std::uint64_t size : folder.unpackSizes) {
        if (size > limits.maxFolderBytes) {
            return fail(ErrorKind::LimitExceeded, "7z folder exceeds size limit", packBase);
        }
    }
    std::uint64_t unpackSize = folder.unpackSizes[folder.finalOutStream];

    std::vector<std::uint64_t> relatives;
    if (folder.packedStreams.empty()) {
        if (folder.numPackedStreams != 1) {
            return fail(ErrorKind::Malformed, "7z folder pack mapping is missing", packBase);
        }
        relatives.push_back(0);
    } else {
        if (folder.packedStreams.size() != folder.numPackedStreams) {
            return fail(ErrorKind::Malformed, "7z folder pack mapping is short", packBase);
        }
        relatives = folder.packedStreams;
    }

    auto last = checkedAdd(firstPackStream, relatives.size());
    if (!last || *last > packs.size()) {
        return fail(ErrorKind::Malformed, "7z folder references no pack stream", packBase);
    }

    plan.unpackSize = unpackSize;
    plan.crc = folder.crc;

    std::uint64_t position = packBase;
    for (std::size_t index = 0; index < relatives.size(); ++index) {
        if (relatives[index] >= folder.numInStreams) {
            return fail(ErrorKind::Malformed, "7z packed stream index is out of range", packBase);
        }

        const PackStream& pack = packs[firstPackStream + index];
        auto end = checkedAdd(position, pack.size);
        if (!end) {
            return fail(ErrorKind::Malformed, "7z pack size overflows", packBase);
        }
        if (*end > fileSize) {
            return fail(ErrorKind::Truncated, "7z pack data extends past end of file", position);
        }

        plan.packs.push_back({.offset = position, .size = pack.size, .crc = pack.crc});
        position = *end;
    }
    return plan;
}

Result<FolderSession> FolderSession::start(
    File file,
    FolderPlan plan,
    const Limits& limits,
    Inflater* inflater,
    Bzip2Decoder* bzip2
) {
    FolderSession session(std::move(file));
    session.plan_ = std::move(plan);
    session.memLimit_ = limits.decoderMemLimitBytes;
    session.inflater_ = inflater;
    session.bzip2_ = bzip2;

    if (!session.plan_.packs.empty()) {
        session.packPosition_ = session.plan_.packs.front().offset;
        const PackSegment& last = session.plan_.packs.back();
        auto end = checkedAdd(last.offset, last.size);
        if (!end) {
            return fail(ErrorKind::Malformed, "7z pack offset overflows");
        }
        session.packDataEnd_ = *end;
    }

    auto prepared = session.prepareDecoder();
    if (!prepared) {
        return tl::unexpected<Error>(prepared.error());
    }
    return session;
}

Result<void> FolderSession::prepareDecoder() {
    useBcj_ = plan_.codec.codec == Codec::Bcj || plan_.codec.bcjFilter;
    decoderFinished_ = false;
    if (plan_.codec.codec == Codec::Bcj) {
        bcj_.reset();
        decoder_.emplace<std::monostate>();
        return {};
    }
    if (useBcj_) {
        bcj_.reset();
    }
    switch (plan_.codec.codec) {
    case Codec::Copy:
        decoder_.emplace<std::monostate>();
        return {};
    case Codec::Deflate:
        if (inflater_ == nullptr) {
            return fail(ErrorKind::LimitExceeded, "7z deflate decoder is missing");
        }
        if (auto reset = inflater_->reset(); !reset) {
            return tl::unexpected<Error>(reset.error());
        }
        decoder_.emplace<Inflater*>(inflater_);
        return {};
    case Codec::Bzip2:
        if (bzip2_ == nullptr) {
            return fail(ErrorKind::LimitExceeded, "7z bzip2 decoder is missing");
        }
        if (auto reset = bzip2_->reset(); !reset) {
            return tl::unexpected<Error>(reset.error());
        }
        decoder_.emplace<Bzip2Decoder*>(bzip2_);
        return {};
    case Codec::Lzma1:
    case Codec::Lzma2: {
        auto decoder = RawLzma::create(plan_.codec.codec, plan_.codec.props, memLimit_);
        if (!decoder) {
            return tl::unexpected<Error>(decoder.error());
        }
        decoder_.emplace<RawLzma>(std::move(*decoder));
        return {};
    }
    case Codec::Bcj:
        return fail(ErrorKind::Malformed, "7z BCJ codec is missing its filter");
    }
    return fail(ErrorKind::Unsupported, "7z codec is not supported");
}

Result<void> FolderSession::startEntry(
    std::uint64_t offset,
    std::uint64_t size,
    std::optional<std::uint32_t> crc,
    std::span<std::byte> scratch
) {
    if (offset < unpackPosition_) {
        return fail(ErrorKind::Malformed, "7z session moved backwards");
    }

    auto end = checkedAdd(offset, size);
    if (!end || *end > plan_.unpackSize) {
        return fail(ErrorKind::Malformed, "7z entry extends past its folder");
    }

    entryBegin_ = offset;
    entryEnd_ = *end;
    entryLeft_ = size;
    entryCrc_ = Crc32{};
    expectedEntryCrc_ = crc;
    entryActive_ = true;
    entryDone_ = false;

    if (plan_.codec.codec == Codec::Copy && !plan_.codec.bcjFilter) {
        if (scratch.empty() && size != 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }
        input_ = scratch;
        output_ = {};
        filterOutput_ = {};
    } else if (plan_.codec.bcjFilter && plan_.codec.codec != Codec::Copy) {
        if (scratch.size() < 3) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer too small for 7z filter chain");
        }
        std::size_t part = scratch.size() / 3;
        input_ = scratch.first(part);
        output_ = scratch.subspan(part, part);
        filterOutput_ = scratch.subspan(part * 2);
    } else {
        if (scratch.size() < 2) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer too small for 7z decode");
        }
        input_ = scratch.first(scratch.size() / 2);
        output_ = scratch.subspan(scratch.size() / 2);
        filterOutput_ = {};
    }

    // NOTE: any read-ahead still buffered is dropped here; the consume cursor
    // already points at the first unconsumed byte, so the next fill re-reads
    // it from the file. This keeps decoding correct for every scratch buffer
    // at the cost of re-reading at most one buffer after each entry boundary.
    pending_ = {};

    if (size == 0) {
        return finishEntry();
    }
    return {};
}

Result<void> FolderSession::finishEntry() {
    if (expectedEntryCrc_ && entryCrc_.value() != *expectedEntryCrc_) {
        return fail(ErrorKind::Integrity, "7z entry CRC-32 mismatch", packPosition_);
    }

    entryActive_ = false;
    entryDone_ = true;

    if (unpackPosition_ == plan_.unpackSize && plan_.crc) {
        if (folderCrc_.value() != *plan_.crc) {
            return fail(ErrorKind::Integrity, "7z folder CRC-32 mismatch", packPosition_);
        }
    }
    return {};
}

Result<void> FolderSession::fillInput() {
    if (!pending_.empty() || packPosition_ >= packDataEnd_) {
        return {};
    }

    std::uint64_t want =
        std::min(static_cast<std::uint64_t>(input_.size()), packDataEnd_ - packPosition_);
    if (want == 0) {
        return {};
    }

    auto room = input_.first(static_cast<std::size_t>(want));
    auto read = file_.readExactAt(packPosition_, room);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    pending_ = room;
    return {};
}

Result<void> FolderSession::noteConsumed(std::size_t count) {
    packCrc_.update(pending_.first(count));

    std::uint64_t left = count;
    while (left > 0) {
        if (packSegment_ >= plan_.packs.size()) {
            return fail(ErrorKind::Truncated, "7z pack data ends before the entry", packPosition_);
        }

        const PackSegment& segment = plan_.packs[packSegment_];
        auto end = checkedAdd(segment.offset, segment.size);
        if (!end || packPosition_ > *end) {
            return fail(ErrorKind::Malformed, "7z pack position overruns its segment");
        }

        std::uint64_t take = std::min(left, *end - packPosition_);
        packPosition_ += take;
        left -= take;

        if (packPosition_ == *end) {
            if (segment.crc && packCrc_.value() != *segment.crc) {
                return fail(ErrorKind::Integrity, "7z pack CRC-32 mismatch", packPosition_);
            }
            ++packSegment_;
            packCrc_ = Crc32{};
        }
    }

    pending_ = pending_.subspan(count);
    return {};
}

Result<std::span<const std::byte>> FolderSession::deliver(std::span<const std::byte> chunk) {
    auto end = checkedAdd(unpackPosition_, chunk.size());
    if (!end || *end > plan_.unpackSize) {
        return fail(ErrorKind::Malformed, "7z folder data exceeds its declared size");
    }

    std::uint64_t chunkStart = unpackPosition_;
    folderCrc_.update(chunk);
    unpackPosition_ = *end;

    if (chunkStart >= entryEnd_) {
        return fail(ErrorKind::Malformed, "7z decode passed its entry");
    }
    if (*end <= entryBegin_) {
        return std::span<const std::byte>{};
    }

    std::size_t skip =
        chunkStart < entryBegin_ ? static_cast<std::size_t>(entryBegin_ - chunkStart) : 0;
    auto part = chunk.subspan(skip);
    entryCrc_.update(part);
    entryLeft_ -= part.size();
    return std::span<const std::byte>(part);
}

Result<std::span<const std::byte>> FolderSession::nextChunk() {
    if (!entryActive_ || entryDone_) {
        return std::span<const std::byte>{};
    }
    if (useBcj_) {
        return nextFiltered();
    }
    if (plan_.codec.codec == Codec::Copy) {
        return nextCopy();
    }
    return nextCoded();
}

Result<std::span<const std::byte>> FolderSession::nextCopy() {
    while (true) {
        if (entryLeft_ == 0) {
            auto finished = finishEntry();
            if (!finished) {
                return tl::unexpected<Error>(finished.error());
            }
            return std::span<const std::byte>{};
        }

        while (packSegment_ < plan_.packs.size()) {
            const PackSegment& segment = plan_.packs[packSegment_];
            auto end = checkedAdd(segment.offset, segment.size);
            if (!end || packPosition_ > *end) {
                return fail(ErrorKind::Malformed, "7z pack position overruns its segment");
            }
            if (packPosition_ != *end) {
                break;
            }
            if (segment.crc && packCrc_.value() != *segment.crc) {
                return fail(ErrorKind::Integrity, "7z pack CRC-32 mismatch", packPosition_);
            }
            ++packSegment_;
            packCrc_ = Crc32{};
        }
        if (packSegment_ >= plan_.packs.size()) {
            return fail(ErrorKind::Truncated, "7z pack data ends before the entry", packPosition_);
        }

        const PackSegment& segment = plan_.packs[packSegment_];
        std::uint64_t segmentLeft = segment.offset + segment.size - packPosition_;
        std::uint64_t want = std::min(
            {entryLeft_,
             static_cast<std::uint64_t>(input_.size()),
             segmentLeft,
             entryEnd_ - unpackPosition_}
        );
        if (want == 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }

        auto chunk = input_.first(static_cast<std::size_t>(want));
        auto read = file_.readExactAt(packPosition_, chunk);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        pending_ = chunk;

        auto consumed = noteConsumed(chunk.size());
        if (!consumed) {
            pending_ = {};
            return tl::unexpected<Error>(consumed.error());
        }

        auto part = deliver(chunk);
        if (!part) {
            return tl::unexpected<Error>(part.error());
        }
        if (!part->empty()) {
            return *part;
        }
    }
}

Result<std::span<const std::byte>> FolderSession::nextCoded() {
    while (true) {
        if (entryLeft_ == 0) {
            auto finished = finishEntry();
            if (!finished) {
                return tl::unexpected<Error>(finished.error());
            }
            return std::span<const std::byte>{};
        }

        if (pending_.empty()) {
            auto filled = fillInput();
            if (!filled) {
                return tl::unexpected<Error>(filled.error());
            }
        }

        std::uint64_t windowSize =
            std::min(static_cast<std::uint64_t>(output_.size()), entryEnd_ - unpackPosition_);
        if (windowSize == 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }
        auto window = output_.first(static_cast<std::size_t>(windowSize));

        Result<DecodeStep> result = DecodeStep{};
        if (auto* inflater = std::get_if<Inflater*>(&decoder_)) {
            result = (*inflater)->decompress(pending_, window);
        } else if (auto* bzip2 = std::get_if<Bzip2Decoder*>(&decoder_)) {
            result = (*bzip2)->decompress(pending_, window);
        } else if (auto* lzma = std::get_if<RawLzma>(&decoder_)) {
            result = lzma->decompress(pending_, window);
        } else {
            return fail(ErrorKind::Malformed, "7z decoder is missing", packPosition_);
        }
        if (!result) {
            auto error = result.error();
            error.offset = packPosition_;
            pending_ = {};
            return tl::unexpected<Error>(error);
        }

        auto consumed = noteConsumed(result->consumed);
        if (!consumed) {
            pending_ = {};
            return tl::unexpected<Error>(consumed.error());
        }

        if (result->produced == 0) {
            if (result->finished) {
                return fail(
                    ErrorKind::Truncated,
                    "7z data stream ends before the entry",
                    packPosition_
                );
            }
            if (result->consumed == 0) {
                if (pending_.empty() && packPosition_ >= packDataEnd_) {
                    return fail(ErrorKind::Truncated, "7z data stream truncated", packPosition_);
                }
                return fail(ErrorKind::Malformed, "7z decoder made no progress", packPosition_);
            }
            continue;
        }

        auto part = deliver(window.first(result->produced));
        if (!part) {
            return tl::unexpected<Error>(part.error());
        }
        if (!part->empty()) {
            return *part;
        }
    }
}

}
