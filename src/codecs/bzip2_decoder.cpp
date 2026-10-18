#include "codecs/decoders.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#include <bzlib.h>

namespace bale {

namespace {

constexpr std::size_t maxStepBytes = std::numeric_limits<unsigned int>::max();

std::unexpected<Error> bzip2Failure(int status) {
    switch (status) {
    case BZ_MEM_ERROR:
        return fail(ErrorKind::LimitExceeded, "bzip2 decoder allocation failed");
    case BZ_UNEXPECTED_EOF:
        return fail(ErrorKind::Truncated, "bzip2 stream truncated");
    case BZ_DATA_ERROR_MAGIC:
        return fail(ErrorKind::Malformed, "not a bzip2 stream");
    case BZ_DATA_ERROR:
        return fail(ErrorKind::Integrity, "bzip2 data integrity check failed");
    case BZ_PARAM_ERROR:
        return fail(ErrorKind::Malformed, "bzip2 decoder call out of sequence");
    default:
        return fail(ErrorKind::Malformed, "bzip2 decoder failed");
    }
}

}

// NOTE: bz_stream keeps pointers into caller buffers across calls, so the state must never
// move after init and every call must clear the pointers before returning.
struct Bzip2Decoder::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        if (initialized) {
            BZ2_bzDecompressEnd(&stream);
        }
    }

    bz_stream stream{};
    bool initialized = false;
    bool ended = false;
};

Bzip2Decoder::Bzip2Decoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

Bzip2Decoder::Bzip2Decoder(Bzip2Decoder&& other) noexcept = default;

Bzip2Decoder& Bzip2Decoder::operator=(Bzip2Decoder&& other) noexcept = default;

Bzip2Decoder::~Bzip2Decoder() = default;

Result<Bzip2Decoder> Bzip2Decoder::create() {
    auto state = std::make_unique<State>();
    int status = BZ2_bzDecompressInit(&state->stream, 0, 0);
    if (status == BZ_MEM_ERROR) {
        return bzip2Failure(status);
    }
    if (status != BZ_OK) {
        return fail(ErrorKind::Unsupported, "bzip2 decoder initialization failed");
    }

    state->initialized = true;
    return Bzip2Decoder(std::move(state));
}

Result<DecodeStep>
Bzip2Decoder::decompress(std::span<const std::byte> input, std::span<std::byte> output) {
    if (state_->ended) {
        return DecodeStep{.finished = true};
    }

    auto inputSize = std::min(input.size(), maxStepBytes);
    auto outputSize = std::min(output.size(), maxStepBytes);
    bz_stream& stream = state_->stream;
    stream.next_in = reinterpret_cast<char*>(const_cast<std::byte*>(input.data()));
    stream.avail_in = static_cast<unsigned int>(inputSize);
    stream.next_out = reinterpret_cast<char*>(output.data());
    stream.avail_out = static_cast<unsigned int>(outputSize);

    int status = BZ2_bzDecompress(&stream);

    DecodeStep step{
        .consumed = inputSize - stream.avail_in,
        .produced = outputSize - stream.avail_out,
    };
    stream.next_in = nullptr;
    stream.avail_in = 0;
    stream.next_out = nullptr;
    stream.avail_out = 0;

    switch (status) {
    case BZ_OK:
        return step;
    case BZ_STREAM_END:
        state_->ended = true;
        step.finished = true;
        return step;
    default:
        return bzip2Failure(status);
    }
}

Result<void> Bzip2Decoder::reset() {
    BZ2_bzDecompressEnd(&state_->stream);
    state_->stream = bz_stream{};
    state_->ended = false;

    int status = BZ2_bzDecompressInit(&state_->stream, 0, 0);
    if (status == BZ_MEM_ERROR) {
        state_->initialized = false;
        return bzip2Failure(status);
    }
    if (status != BZ_OK) {
        state_->initialized = false;
        return fail(ErrorKind::Malformed, "bzip2 decoder reset failed");
    }
    return {};
}

bool Bzip2Decoder::streamEnded() const {
    return state_->ended;
}

}
