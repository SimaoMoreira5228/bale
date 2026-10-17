#include "codecs/decoders.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include <zlib-ng.h>

namespace bale {

namespace {

constexpr int rawWindowBits = -15;

constexpr std::size_t maxStepBytes = std::numeric_limits<std::uint32_t>::max();

}

// NOTE: zlib-ng keeps a back pointer to the stream, so the state must never move after init.
struct Inflater::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        if (initialized) {
            zng_inflateEnd(&stream);
        }
    }

    zng_stream stream{};
    bool initialized = false;
    bool finished = false;
};

Inflater::Inflater(std::unique_ptr<State> state) : state_(std::move(state)) {
}

Inflater::Inflater(Inflater&& other) noexcept = default;

Inflater& Inflater::operator=(Inflater&& other) noexcept = default;

Inflater::~Inflater() = default;

Result<Inflater> Inflater::create() {
    auto state = std::make_unique<State>();
    int status = zng_inflateInit2(&state->stream, rawWindowBits);
    if (status == Z_MEM_ERROR) {
        return fail(ErrorKind::LimitExceeded, "deflate decoder allocation failed");
    }
    if (status != Z_OK) {
        return fail(ErrorKind::Unsupported, "deflate decoder initialization failed");
    }

    state->initialized = true;
    return Inflater(std::move(state));
}

Result<DecodeStep>
Inflater::decompress(std::span<const std::byte> input, std::span<std::byte> output) {
    if (state_->finished) {
        return DecodeStep{.finished = true};
    }

    auto inputSize = std::min(input.size(), maxStepBytes);
    auto outputSize = std::min(output.size(), maxStepBytes);
    zng_stream& stream = state_->stream;
    stream.next_in = reinterpret_cast<const std::uint8_t*>(input.data());
    stream.avail_in = static_cast<std::uint32_t>(inputSize);
    stream.next_out = reinterpret_cast<std::uint8_t*>(output.data());
    stream.avail_out = static_cast<std::uint32_t>(outputSize);

    int status = zng_inflate(&stream, Z_NO_FLUSH);

    DecodeStep step{
        .consumed = inputSize - stream.avail_in,
        .produced = outputSize - stream.avail_out,
    };
    stream.next_in = nullptr;
    stream.avail_in = 0;
    stream.next_out = nullptr;
    stream.avail_out = 0;

    switch (status) {
    case Z_OK:
    case Z_BUF_ERROR:
        return step;
    case Z_STREAM_END:
        state_->finished = true;
        step.finished = true;
        return step;
    case Z_DATA_ERROR:
        return fail(ErrorKind::Malformed, "invalid deflate stream");
    case Z_MEM_ERROR:
        return fail(ErrorKind::LimitExceeded, "deflate decoder allocation failed");
    default:
        return fail(ErrorKind::Malformed, "deflate decoder failed");
    }
}

Result<void> Inflater::reset() {
    if (zng_inflateReset(&state_->stream) != Z_OK) {
        return fail(ErrorKind::Malformed, "deflate decoder reset failed");
    }

    state_->finished = false;
    return {};
}

}
