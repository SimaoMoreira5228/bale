#include "codecs/encoders.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include <zlib-ng.h>

namespace bale {

namespace {

constexpr int rawWindowBits = -15;
constexpr int defaultMemoryLevel = 8;
constexpr std::size_t maxStepBytes = std::numeric_limits<std::uint32_t>::max();

int flushMode(EncodeFlush flush) {
    switch (flush) {
    case EncodeFlush::None:
        return Z_NO_FLUSH;
    case EncodeFlush::Sync:
        return Z_SYNC_FLUSH;
    case EncodeFlush::Finish:
        return Z_FINISH;
    }
    return Z_NO_FLUSH;
}

}

// NOTE: zlib-ng keeps a back pointer to the stream, so the state must never move after init.
struct DeflateEncoder::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        if (initialized) {
            zng_deflateEnd(&stream);
        }
    }

    zng_stream stream{};
    bool initialized = false;
};

DeflateEncoder::DeflateEncoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

DeflateEncoder::DeflateEncoder(DeflateEncoder&& other) noexcept = default;

DeflateEncoder& DeflateEncoder::operator=(DeflateEncoder&& other) noexcept = default;

DeflateEncoder::~DeflateEncoder() = default;

Result<DeflateEncoder> DeflateEncoder::create(int compressionLevel) {
    if (compressionLevel < 0 || compressionLevel > 9) {
        return fail(ErrorKind::Unsupported, "deflate compression level out of range");
    }

    auto state = std::make_unique<State>();
    int status = zng_deflateInit2(
        &state->stream,
        compressionLevel,
        Z_DEFLATED,
        rawWindowBits,
        defaultMemoryLevel,
        Z_DEFAULT_STRATEGY
    );
    if (status == Z_MEM_ERROR) {
        return fail(ErrorKind::LimitExceeded, "deflate encoder allocation failed");
    }
    if (status != Z_OK) {
        return fail(ErrorKind::Unsupported, "deflate encoder initialization failed");
    }
    state->initialized = true;
    return DeflateEncoder(std::move(state));
}

std::size_t DeflateEncoder::compressBound(std::size_t inputSize) {
    if (inputSize > std::numeric_limits<std::uint32_t>::max()) {
        return 0;
    }
    return zng_deflateBound(nullptr, static_cast<unsigned long>(inputSize));
}

Result<std::size_t>
DeflateEncoder::compress(std::span<const std::byte> input, std::span<std::byte> output) {
    constexpr std::size_t maxStep = std::numeric_limits<std::uint32_t>::max();
    if (input.size() > maxStep || output.size() > maxStep) {
        return fail(ErrorKind::LimitExceeded, "deflate buffer exceeds 4 GiB");
    }

    zng_stream& stream = state_->stream;
    if (zng_deflateReset(&stream) != Z_OK) {
        return fail(ErrorKind::Malformed, "deflate encoder reset failed");
    }

    stream.next_in = reinterpret_cast<const std::uint8_t*>(input.data());
    stream.avail_in = static_cast<std::uint32_t>(input.size());
    stream.next_out = reinterpret_cast<std::uint8_t*>(output.data());
    stream.avail_out = static_cast<std::uint32_t>(output.size());
    int status = zng_deflate(&stream, Z_FINISH);
    if (status == Z_STREAM_END) {
        return output.size() - stream.avail_out;
    }
    if (status == Z_OK || status == Z_BUF_ERROR) {
        return fail(ErrorKind::LimitExceeded, "deflate output buffer is too small");
    }
    return fail(ErrorKind::Malformed, "deflate compression failed");
}

Result<EncodeStep> DeflateEncoder::stream(
    std::span<const std::byte> input,
    std::span<std::byte> output,
    EncodeFlush flush
) {
    auto inputSize = std::min(input.size(), maxStepBytes);
    auto outputSize = std::min(output.size(), maxStepBytes);
    if (inputSize < input.size()) {
        flush = EncodeFlush::None;
    }

    zng_stream& stream = state_->stream;
    stream.next_in = reinterpret_cast<const std::uint8_t*>(input.data());
    stream.avail_in = static_cast<std::uint32_t>(inputSize);
    stream.next_out = reinterpret_cast<std::uint8_t*>(output.data());
    stream.avail_out = static_cast<std::uint32_t>(outputSize);

    int status = zng_deflate(&stream, flushMode(flush));

    EncodeStep step{
        .consumed = inputSize - stream.avail_in,
        .produced = outputSize - stream.avail_out,
    };
    bool drained = stream.avail_in == 0 && stream.avail_out != 0;
    stream.next_in = nullptr;
    stream.avail_in = 0;
    stream.next_out = nullptr;
    stream.avail_out = 0;

    switch (status) {
    case Z_STREAM_END:
        step.finished = true;
        return step;
    case Z_OK:
    case Z_BUF_ERROR:
        step.finished = flush != EncodeFlush::Finish && drained;
        return step;
    default:
        return fail(ErrorKind::Malformed, "deflate compression failed");
    }
}

Result<void> DeflateEncoder::reset() {
    if (zng_deflateReset(&state_->stream) != Z_OK) {
        return fail(ErrorKind::Malformed, "deflate encoder reset failed");
    }
    return {};
}

}
