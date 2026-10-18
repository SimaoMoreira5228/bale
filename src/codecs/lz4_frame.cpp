#include "codecs/lz4_frame.hpp"

#include <utility>

#include <lz4frame.h>

namespace bale {

namespace {

LZ4F_blockSizeID_t blockSizeFor(std::size_t inputSize) {
    constexpr std::size_t kilobyte = 1024;
    if (inputSize <= 64 * kilobyte) {
        return LZ4F_max64KB;
    }
    if (inputSize <= 256 * kilobyte) {
        return LZ4F_max256KB;
    }
    if (inputSize <= 1024 * kilobyte) {
        return LZ4F_max1MB;
    }
    return LZ4F_max4MB;
}

LZ4F_preferences_t preferencesFor(std::size_t inputSize, int compressionLevel) {
    LZ4F_preferences_t preferences{};
    preferences.frameInfo.blockSizeID = blockSizeFor(inputSize);
    preferences.frameInfo.blockMode = LZ4F_blockIndependent;
    preferences.frameInfo.contentChecksumFlag = LZ4F_noContentChecksum;
    preferences.frameInfo.frameType = LZ4F_frame;
    preferences.frameInfo.contentSize = inputSize;
    preferences.frameInfo.dictID = 0;
    preferences.frameInfo.blockChecksumFlag = LZ4F_noBlockChecksum;
    preferences.compressionLevel = compressionLevel;
    preferences.autoFlush = 1;
    return preferences;
}

Result<void> checkFrameInfo(const LZ4F_frameInfo_t& info, std::size_t expectedSize) {
    if (info.frameType != LZ4F_frame) {
        return fail(ErrorKind::Malformed, "lz4 skippable frame instead of data", 0);
    }
    if (info.blockMode != LZ4F_blockIndependent) {
        return fail(ErrorKind::Malformed, "lz4 frame has linked blocks", 0);
    }
    if (info.contentChecksumFlag != LZ4F_noContentChecksum ||
        info.blockChecksumFlag != LZ4F_noBlockChecksum) {
        return fail(ErrorKind::Malformed, "lz4 frame carries a checksum", 0);
    }
    if (info.dictID != 0) {
        return fail(ErrorKind::Malformed, "lz4 frame names a dictionary", 0);
    }
    if (info.contentSize == 0) {
        return fail(ErrorKind::Malformed, "lz4 frame lacks its content size", 0);
    }
    if (info.contentSize != expectedSize) {
        return fail(ErrorKind::Malformed, "lz4 frame content size differs from the chunk", 0);
    }
    return {};
}

}

struct Lz4FrameEncoder::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        LZ4F_freeCompressionContext(context);
    }

    LZ4F_cctx* context = nullptr;
    int compressionLevel = minLz4Level;
};

Lz4FrameEncoder::Lz4FrameEncoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

Lz4FrameEncoder::Lz4FrameEncoder(Lz4FrameEncoder&& other) noexcept = default;

Lz4FrameEncoder& Lz4FrameEncoder::operator=(Lz4FrameEncoder&& other) noexcept = default;

Lz4FrameEncoder::~Lz4FrameEncoder() = default;

Result<Lz4FrameEncoder> Lz4FrameEncoder::create(int compressionLevel) {
    if (compressionLevel < minLz4Level || compressionLevel > maxLz4Level) {
        return fail(ErrorKind::Unsupported, "lz4 compression level out of range");
    }

    auto state = std::make_unique<State>();
    state->compressionLevel = compressionLevel;
    if (LZ4F_isError(LZ4F_createCompressionContext(&state->context, LZ4F_VERSION))) {
        return fail(ErrorKind::LimitExceeded, "lz4 encoder allocation failed");
    }
    return Lz4FrameEncoder(std::move(state));
}

std::size_t Lz4FrameEncoder::compressBound(std::size_t inputSize) {
    auto preferences = preferencesFor(inputSize, minLz4Level);
    return LZ4F_compressFrameBound(inputSize, &preferences);
}

Result<std::size_t>
Lz4FrameEncoder::compress(std::span<const std::byte> input, std::span<std::byte> output) {
    if (input.empty()) {
        return fail(ErrorKind::Unsupported, "lz4 frame cannot record an empty content size");
    }

    auto preferences = preferencesFor(input.size(), state_->compressionLevel);
    if (output.size() < LZ4F_compressFrameBound(input.size(), &preferences)) {
        return fail(ErrorKind::LimitExceeded, "lz4 output buffer is too small");
    }

    LZ4F_compressOptions_t options{};
    options.stableSrc = 1;
    std::size_t written =
        LZ4F_compressBegin(state_->context, output.data(), output.size(), &preferences);
    if (LZ4F_isError(written)) {
        return fail(ErrorKind::Malformed, "lz4 compression failed");
    }

    std::size_t body = LZ4F_compressUpdate(
        state_->context,
        output.data() + written,
        output.size() - written,
        input.data(),
        input.size(),
        &options
    );
    if (LZ4F_isError(body)) {
        return fail(ErrorKind::Malformed, "lz4 compression failed");
    }
    written += body;

    std::size_t end = LZ4F_compressEnd(
        state_->context,
        output.data() + written,
        output.size() - written,
        &options
    );
    if (LZ4F_isError(end)) {
        return fail(ErrorKind::Malformed, "lz4 compression failed");
    }
    return written + end;
}

struct Lz4FrameDecoder::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        LZ4F_freeDecompressionContext(context);
    }

    LZ4F_dctx* context = nullptr;
};

Lz4FrameDecoder::Lz4FrameDecoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

Lz4FrameDecoder::Lz4FrameDecoder(Lz4FrameDecoder&& other) noexcept = default;

Lz4FrameDecoder& Lz4FrameDecoder::operator=(Lz4FrameDecoder&& other) noexcept = default;

Lz4FrameDecoder::~Lz4FrameDecoder() = default;

Result<Lz4FrameDecoder> Lz4FrameDecoder::create() {
    auto state = std::make_unique<State>();
    if (LZ4F_isError(LZ4F_createDecompressionContext(&state->context, LZ4F_VERSION))) {
        return fail(ErrorKind::LimitExceeded, "lz4 decoder allocation failed");
    }
    return Lz4FrameDecoder(std::move(state));
}

Result<void>
Lz4FrameDecoder::decompress(std::span<const std::byte> frame, std::span<std::byte> output) {
    LZ4F_dctx* context = state_->context;
    LZ4F_resetDecompressionContext(context);

    LZ4F_frameInfo_t info{};
    std::size_t consumed = frame.size();
    std::size_t hint = LZ4F_getFrameInfo(context, &info, frame.data(), &consumed);
    if (LZ4F_isError(hint)) {
        return fail(ErrorKind::Malformed, "invalid lz4 frame header", 0);
    }
    auto valid = checkFrameInfo(info, output.size());
    if (!valid) {
        return valid;
    }

    LZ4F_decompressOptions_t options{};
    options.stableDst = 1;
    std::size_t produced = 0;
    while (hint != 0) {
        std::size_t inputSize = frame.size() - consumed;
        std::size_t outputSize = output.size() - produced;
        hint = LZ4F_decompress(
            context,
            output.data() + produced,
            &outputSize,
            frame.data() + consumed,
            &inputSize,
            &options
        );
        if (LZ4F_isError(hint)) {
            return fail(ErrorKind::Malformed, "invalid lz4 frame", consumed);
        }

        consumed += inputSize;
        produced += outputSize;
        if (hint == 0 || inputSize != 0 || outputSize != 0) {
            continue;
        }
        if (consumed == frame.size()) {
            return fail(ErrorKind::Truncated, "lz4 frame is truncated", consumed);
        }
        return fail(ErrorKind::Malformed, "lz4 frame exceeds the chunk size", consumed);
    }

    if (consumed != frame.size()) {
        return fail(ErrorKind::Malformed, "trailing bytes after the lz4 frame", consumed);
    }
    if (produced != output.size()) {
        return fail(ErrorKind::Malformed, "lz4 frame size differs from the chunk", consumed);
    }
    return {};
}

}
