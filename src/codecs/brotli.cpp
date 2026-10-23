#include "codecs/brotli.hpp"

#include "base/checked.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

#include <brotli/decode.h>
#include <brotli/encode.h>

namespace bale {

namespace {

tl::unexpected<Error> brotliEncodeFailure() {
    return fail(ErrorKind::LimitExceeded, "brotli output buffer is too small");
}

tl::unexpected<Error> brotliDecodeFailure(BrotliDecoderErrorCode code) {
    switch (code) {
    case BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MODES:
    case BROTLI_DECODER_ERROR_ALLOC_TREE_GROUPS:
    case BROTLI_DECODER_ERROR_ALLOC_CONTEXT_MAP:
    case BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_1:
    case BROTLI_DECODER_ERROR_ALLOC_RING_BUFFER_2:
    case BROTLI_DECODER_ERROR_ALLOC_BLOCK_TYPE_TREES:
        return fail(ErrorKind::LimitExceeded, "brotli decoder allocation failed");
    case BROTLI_DECODER_ERROR_FORMAT_WINDOW_BITS:
        return fail(ErrorKind::Unsupported, "brotli stream needs an unsupported window");
    case BROTLI_DECODER_NO_ERROR:
    case BROTLI_DECODER_SUCCESS:
    case BROTLI_DECODER_NEEDS_MORE_INPUT:
    case BROTLI_DECODER_NEEDS_MORE_OUTPUT:
        return fail(ErrorKind::Malformed, "brotli decoder failed");
    default:
        return fail(ErrorKind::Malformed, "brotli stream is malformed");
    }
}

}

struct BrotliEncoder::State {
    int compressionLevel = BROTLI_DEFAULT_QUALITY;
};

BrotliEncoder::BrotliEncoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

BrotliEncoder::BrotliEncoder(BrotliEncoder&& other) noexcept = default;

BrotliEncoder& BrotliEncoder::operator=(BrotliEncoder&& other) noexcept = default;

BrotliEncoder::~BrotliEncoder() = default;

Result<BrotliEncoder> BrotliEncoder::create(int compressionLevel) {
    if (compressionLevel < minBrotliLevel || compressionLevel > maxBrotliLevel) {
        return fail(ErrorKind::Unsupported, "brotli compression level out of range");
    }

    auto state = std::make_unique<State>();
    state->compressionLevel = compressionLevel;
    return BrotliEncoder(std::move(state));
}

std::size_t BrotliEncoder::compressBound(std::size_t inputSize) {
    std::size_t bound = BrotliEncoderMaxCompressedSize(inputSize);
    if (bound != 0) {
        return bound;
    }

    auto fallback = checkedAdd(inputSize, inputSize / 3);
    if (!fallback) {
        return 0;
    }
    auto padded = checkedAdd(*fallback, std::size_t{256});
    if (!padded) {
        return 0;
    }
    return *padded;
}

Result<std::size_t>
BrotliEncoder::compress(std::span<const std::byte> input, std::span<std::byte> output) {
    std::size_t encodedSize = output.size();
    auto ok = BrotliEncoderCompress(
        state_->compressionLevel,
        BROTLI_DEFAULT_WINDOW,
        BROTLI_MODE_GENERIC,
        input.size(),
        reinterpret_cast<const std::uint8_t*>(input.data()),
        &encodedSize,
        reinterpret_cast<std::uint8_t*>(output.data())
    );
    if (ok != BROTLI_TRUE) {
        return brotliEncodeFailure();
    }
    return encodedSize;
}

// NOTE: the decoder instance is single-use upstream, so reset destroys it and builds a new
// one; the large-window extension stays off, which caps the ring buffer at 2^24 bytes.
struct BrotliDecoder::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        if (decoder != nullptr) {
            BrotliDecoderDestroyInstance(decoder);
        }
    }

    BrotliDecoderState* decoder = nullptr;
};

BrotliDecoder::BrotliDecoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

BrotliDecoder::BrotliDecoder(BrotliDecoder&& other) noexcept = default;

BrotliDecoder& BrotliDecoder::operator=(BrotliDecoder&& other) noexcept = default;

BrotliDecoder::~BrotliDecoder() = default;

Result<BrotliDecoder> BrotliDecoder::create() {
    auto state = std::make_unique<State>();
    state->decoder = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (state->decoder == nullptr) {
        return fail(ErrorKind::LimitExceeded, "brotli decoder allocation failed");
    }
    return BrotliDecoder(std::move(state));
}

Result<DecodeStep> BrotliDecoder::decompress(
    std::span<const std::byte> input,
    std::span<std::byte> output,
    bool finish
) {
    constexpr std::size_t maxStepBytes = std::numeric_limits<std::uint32_t>::max();
    auto inputSize = std::min(input.size(), maxStepBytes);
    auto outputSize = std::min(output.size(), maxStepBytes);

    const std::uint8_t* nextIn = reinterpret_cast<const std::uint8_t*>(input.data());
    std::uint8_t* nextOut = reinterpret_cast<std::uint8_t*>(output.data());
    std::size_t availableIn = inputSize;
    std::size_t availableOut = outputSize;
    auto status = BrotliDecoderDecompressStream(
        state_->decoder,
        &availableIn,
        &nextIn,
        &availableOut,
        &nextOut,
        nullptr
    );

    DecodeStep step{
        .consumed = inputSize - availableIn,
        .produced = outputSize - availableOut,
    };
    switch (status) {
    case BROTLI_DECODER_RESULT_SUCCESS:
        step.finished = true;
        return step;
    case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
        return step;
    case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
        if (finish) {
            return fail(ErrorKind::Truncated, "brotli stream truncated");
        }
        return step;
    default:
        return brotliDecodeFailure(BrotliDecoderGetErrorCode(state_->decoder));
    }
}

Result<void> BrotliDecoder::reset() {
    BrotliDecoderState* decoder = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (decoder == nullptr) {
        return fail(ErrorKind::LimitExceeded, "brotli decoder allocation failed");
    }
    BrotliDecoderDestroyInstance(state_->decoder);
    state_->decoder = decoder;
    return {};
}

}
