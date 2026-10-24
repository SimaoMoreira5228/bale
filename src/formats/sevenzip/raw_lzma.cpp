#include "formats/sevenzip/folder.hpp"

#include "base/endian.hpp"

#include <algorithm>
#include <limits>

#include <lzma.h>

namespace bale::sevenzip {

namespace {

constexpr std::size_t maxStepBytes = std::numeric_limits<std::uint32_t>::max();
constexpr std::uint32_t lzmaDictMin = 1U << 12;

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

}
