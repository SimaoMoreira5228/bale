#include "codecs/decoders.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include <lzma.h>

namespace bale {

namespace {

constexpr std::size_t maxStepBytes = std::numeric_limits<std::uint32_t>::max();

tl::unexpected<Error> xzFailure(lzma_ret status) {
    switch (status) {
    case LZMA_MEMLIMIT_ERROR:
        return fail(ErrorKind::LimitExceeded, "xz decoder memory limit exceeded");
    case LZMA_MEM_ERROR:
        return fail(ErrorKind::LimitExceeded, "xz decoder allocation failed");
    case LZMA_FORMAT_ERROR:
        return fail(ErrorKind::Malformed, "not an xz stream");
    case LZMA_OPTIONS_ERROR:
        return fail(ErrorKind::Unsupported, "xz stream needs unsupported options");
    case LZMA_DATA_ERROR:
        return fail(ErrorKind::Integrity, "xz data integrity check failed");
    case LZMA_BUF_ERROR:
        return fail(ErrorKind::Truncated, "xz stream truncated");
    case LZMA_NO_CHECK:
    case LZMA_UNSUPPORTED_CHECK:
        return fail(ErrorKind::Unsupported, "xz stream needs an unsupported integrity check");
    default:
        return fail(ErrorKind::Malformed, "xz decoder failed");
    }
}

}

// NOTE: lzma_stream keeps pointers into caller buffers across calls, so the state must
// never move after init and every call must clear the pointers before returning.
struct XzDecoder::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        if (initialized) {
            lzma_end(&stream);
        }
    }

    lzma_stream stream = LZMA_STREAM_INIT;
    std::uint64_t memLimit = 0;
    bool initialized = false;
    bool ended = false;
};

XzDecoder::XzDecoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

XzDecoder::XzDecoder(XzDecoder&& other) noexcept = default;

XzDecoder& XzDecoder::operator=(XzDecoder&& other) noexcept = default;

XzDecoder::~XzDecoder() = default;

Result<XzDecoder> XzDecoder::create(const XzLimits& limits) {
    if (limits.memLimitBytes == 0) {
        return fail(ErrorKind::LimitExceeded, "xz memory limit is zero");
    }

    auto state = std::make_unique<State>();
    auto status = lzma_auto_decoder(&state->stream, limits.memLimitBytes, 0);
    if (status == LZMA_MEM_ERROR) {
        return fail(ErrorKind::LimitExceeded, "xz decoder allocation failed");
    }
    if (status != LZMA_OK) {
        return fail(ErrorKind::Unsupported, "xz decoder initialization failed");
    }

    state->memLimit = limits.memLimitBytes;
    state->initialized = true;
    return XzDecoder(std::move(state));
}

Result<DecodeStep>
XzDecoder::decompress(std::span<const std::byte> input, std::span<std::byte> output, bool finish) {
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

    auto status = lzma_code(&stream, finish ? LZMA_FINISH : LZMA_RUN);

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
        return xzFailure(status);
    }
}

Result<void> XzDecoder::reset() {
    lzma_end(&state_->stream);
    state_->stream = LZMA_STREAM_INIT;
    state_->ended = false;

    auto status = lzma_auto_decoder(&state_->stream, state_->memLimit, 0);
    if (status == LZMA_MEM_ERROR) {
        state_->initialized = false;
        return fail(ErrorKind::LimitExceeded, "xz decoder allocation failed");
    }
    if (status != LZMA_OK) {
        state_->initialized = false;
        return fail(ErrorKind::Malformed, "xz decoder reset failed");
    }
    return {};
}

bool XzDecoder::streamEnded() const {
    return state_->ended;
}

}
