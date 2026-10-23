#include "formats/sevenzip/folder.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "formats/sevenzip/methods.hpp"

#include <algorithm>
#include <array>
#include <limits>

#include <lzma.h>

namespace bale::sevenzip {

namespace {

constexpr std::size_t maxStepBytes = std::numeric_limits<std::uint32_t>::max();
constexpr std::uint32_t lzmaDictMin = 1U << 12;

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

tl::unexpected<Error> lzmaFailure(lzma_ret status) {
    switch (status) {
    case LZMA_MEMLIMIT_ERROR:
        return fail(ErrorKind::LimitExceeded, "7z lzma decoder memory limit exceeded");
    case LZMA_MEM_ERROR:
        return fail(ErrorKind::LimitExceeded, "7z lzma decoder allocation failed");
    case LZMA_FORMAT_ERROR:
        return fail(ErrorKind::Malformed, "not a 7z lzma stream");
    case LZMA_OPTIONS_ERROR:
        return fail(ErrorKind::Malformed, "7z lzma properties are invalid");
    case LZMA_DATA_ERROR:
        return fail(ErrorKind::Integrity, "7z lzma data integrity check failed");
    case LZMA_BUF_ERROR:
        return fail(ErrorKind::Truncated, "7z lzma stream truncated");
    default:
        return fail(ErrorKind::Malformed, "7z lzma decoder failed");
    }
}

std::uint64_t lzma2DictSize(std::uint8_t props) {
    return (std::uint64_t{2} | (props & 1)) << (props / 2 + 11);
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

    std::uint64_t unpackSize = 0;
    for (std::uint64_t size : folder.unpackSizes) {
        auto next = checkedAdd(unpackSize, size);
        if (!next) {
            return fail(ErrorKind::Malformed, "7z folder unpack size overflows", packBase);
        }
        unpackSize = *next;
    }
    if (unpackSize > limits.maxFolderBytes) {
        return fail(ErrorKind::LimitExceeded, "7z folder exceeds size limit", packBase);
    }

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

struct RawLzma::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        if (initialized) {
            lzma_end(&stream);
        }
    }

    lzma_stream stream = LZMA_STREAM_INIT;
    lzma_options_lzma options;
    lzma_filter filters[2] = {};
    bool initialized = false;
    bool ended = false;
};

RawLzma::RawLzma(std::unique_ptr<State> state) : state_(std::move(state)) {
}

RawLzma::RawLzma(RawLzma&& other) noexcept = default;

RawLzma& RawLzma::operator=(RawLzma&& other) noexcept = default;

RawLzma::~RawLzma() = default;

Result<RawLzma>
RawLzma::create(Codec codec, std::span<const std::byte> props, std::uint64_t memLimitBytes) {
    if (memLimitBytes == 0) {
        return fail(ErrorKind::LimitExceeded, "7z lzma memory limit is zero");
    }

    auto state = std::make_unique<State>();
    state->options.preset_dict = nullptr;
    state->options.preset_dict_size = 0;
    state->options.mode = LZMA_MODE_NORMAL;
    state->options.nice_len = 64;
    state->options.mf = LZMA_MF_HC4;
    state->options.depth = 0;
    std::uint64_t dictSize = 0;
    if (codec == Codec::Lzma1) {
        if (props.size() != 5) {
            return fail(ErrorKind::Malformed, "7z LZMA1 properties have the wrong size");
        }

        std::uint8_t first = std::to_integer<std::uint8_t>(props[0]);
        std::uint8_t literalContext = first % 9;
        std::uint8_t remainder = first / 9;
        std::uint8_t literalPosition = remainder % 5;
        std::uint8_t position = remainder / 5;
        if (literalContext > 8 || literalPosition > 4 || position > 4) {
            return fail(ErrorKind::Malformed, "7z LZMA1 properties are invalid");
        }

        dictSize = loadLe<std::uint32_t>(props.data() + 1);
        if (dictSize < lzmaDictMin) {
            return fail(ErrorKind::Malformed, "7z LZMA1 dictionary is too small");
        }

        state->options.lc = literalContext;
        state->options.lp = literalPosition;
        state->options.pb = position;
        state->filters[0].id = LZMA_FILTER_LZMA1;
    } else if (codec == Codec::Lzma2) {
        if (props.size() != 1) {
            return fail(ErrorKind::Malformed, "7z LZMA2 properties have the wrong size");
        }

        std::uint8_t bits = std::to_integer<std::uint8_t>(props[0]);
        if (bits > 40) {
            return fail(ErrorKind::Malformed, "7z LZMA2 properties are invalid");
        }
        dictSize = lzma2DictSize(bits);

        state->options.lc = 3;
        state->options.lp = 0;
        state->options.pb = 2;
        state->filters[0].id = LZMA_FILTER_LZMA2;
    } else {
        return fail(ErrorKind::Malformed, "7z codec is not an LZMA variant");
    }

    if (dictSize > memLimitBytes) {
        return fail(ErrorKind::LimitExceeded, "7z lzma dictionary exceeds decoder memory limit");
    }
    state->options.dict_size = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(dictSize, std::uint64_t{std::numeric_limits<std::uint32_t>::max()})
    );
    state->filters[0].options = &state->options;
    state->filters[1].id = LZMA_VLI_UNKNOWN;

    auto status = lzma_raw_decoder(&state->stream, state->filters);
    if (status == LZMA_MEM_ERROR) {
        return fail(ErrorKind::LimitExceeded, "7z lzma decoder allocation failed");
    }
    if (status != LZMA_OK) {
        return fail(ErrorKind::Malformed, "7z lzma decoder initialization failed");
    }
    state->initialized = true;
    return RawLzma(std::move(state));
}

Result<DecodeStep>
RawLzma::decompress(std::span<const std::byte> input, std::span<std::byte> output) {
    if (state_->ended) {
        return DecodeStep{.finished = true};
    }

    auto inputSize = std::min(input.size(), maxStepBytes);
    auto outputSize = std::min(output.size(), maxStepBytes);
    lzma_stream& stream = state_->stream;
    stream.next_in = reinterpret_cast<const std::uint8_t*>(input.data());
    stream.avail_in = inputSize;
    stream.next_out = reinterpret_cast<std::uint8_t*>(output.data());
    stream.avail_out = outputSize;

    auto status = lzma_code(&stream, LZMA_RUN);

    DecodeStep step{
        .consumed = inputSize - stream.avail_in,
        .produced = outputSize - stream.avail_out,
    };
    stream.next_in = nullptr;
    stream.avail_in = 0;
    stream.next_out = nullptr;
    stream.avail_out = 0;

    switch (status) {
    case LZMA_OK:
        return step;
    case LZMA_STREAM_END:
        state_->ended = true;
        step.finished = true;
        return step;
    default:
        return lzmaFailure(status);
    }
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
    useBcj_ = plan_.codec.codec == Codec::Bcj;
    if (useBcj_) {
        bcj_.reset();
        decoder_.emplace<std::monostate>();
        return {};
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

    if (plan_.codec.codec == Codec::Copy) {
        if (scratch.empty() && size != 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }
        input_ = scratch;
        output_ = {};
    } else {
        if (scratch.size() < 2) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer too small for 7z decode");
        }
        input_ = scratch.first(scratch.size() / 2);
        output_ = scratch.subspan(scratch.size() / 2);
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

Result<std::span<const std::byte>> FolderSession::nextFiltered() {
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

        if (!pending_.empty()) {
            auto step = bcj_.filter(pending_, window);
            if (!step) {
                auto error = step.error();
                error.offset = packPosition_;
                pending_ = {};
                return tl::unexpected<Error>(error);
            }

            auto consumed = noteConsumed(step->consumed);
            if (!consumed) {
                pending_ = {};
                return tl::unexpected<Error>(consumed.error());
            }

            if (step->produced > 0) {
                auto part = deliver(window.first(step->produced));
                if (!part) {
                    return tl::unexpected<Error>(part.error());
                }
                if (!part->empty()) {
                    return *part;
                }
                continue;
            }
        }

        if (pending_.empty() && packPosition_ >= packDataEnd_) {
            auto flushed = bcj_.flush(window);
            if (!flushed) {
                return tl::unexpected<Error>(flushed.error());
            }
            if (*flushed == 0) {
                return fail(ErrorKind::Truncated, "7z data stream truncated", packPosition_);
            }
            auto part = deliver(window.first(*flushed));
            if (!part) {
                return tl::unexpected<Error>(part.error());
            }
            if (!part->empty()) {
                return *part;
            }
            continue;
        }

        if (pending_.empty()) {
            continue;
        }
        return fail(ErrorKind::Malformed, "7z filter made no progress", packPosition_);
    }
}

}
