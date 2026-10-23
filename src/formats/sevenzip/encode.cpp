#include "formats/sevenzip/encode.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "codecs/encoders.hpp"

#include <algorithm>
#include <array>
#include <limits>

#include <bzlib.h>
#include <lzma.h>

namespace bale::sevenzip {

namespace {

constexpr std::size_t maxStepBytes = std::numeric_limits<std::uint32_t>::max();
constexpr std::uint64_t lzma1MinDictBytes = std::uint64_t{1} << 12;
constexpr std::uint8_t lzma1LiteralContext = 3;
constexpr std::uint8_t lzma1LiteralPosition = 0;
constexpr std::uint8_t lzma1PositionBits = 2;

std::unexpected<Error> lzmaEncodeFailure(lzma_ret status) {
    switch (status) {
    case LZMA_MEM_ERROR:
        return fail(ErrorKind::LimitExceeded, "7z lzma encoder allocation failed");
    case LZMA_OPTIONS_ERROR:
        return fail(ErrorKind::Unsupported, "7z compression level out of range");
    case LZMA_MEMLIMIT_ERROR:
        return fail(ErrorKind::LimitExceeded, "7z lzma encoder memory limit exceeded");
    case LZMA_BUF_ERROR:
        return fail(ErrorKind::LimitExceeded, "7z lzma output buffer is too small");
    default:
        return fail(ErrorKind::Malformed, "7z lzma compression failed");
    }
}

std::uint8_t lzma2PropsByte(std::uint64_t dictBytes) {
    for (unsigned props = 0; props <= 40; ++props) {
        std::uint64_t candidate = (std::uint64_t{2} | (props & 1)) << (props / 2 + 11);
        if (candidate == dictBytes) {
            return static_cast<std::uint8_t>(props);
        }
    }
    return 0;
}

}

struct FolderEncoder::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        if (lzmaReady) {
            lzma_end(&lzma);
        }
        if (bzip2Ready) {
            BZ2_bzCompressEnd(&bzip2);
        }
    }

    std::optional<DeflateEncoder> deflate;
    lzma_stream lzma = LZMA_STREAM_INIT;
    bz_stream bzip2{};
    std::vector<std::byte> output;
    bool lzmaReady = false;
    bool bzip2Ready = false;
    bool ended = false;
};

FolderEncoder::FolderEncoder(std::unique_ptr<State> state, Codec codec) :
    state_(std::move(state)), codec_(codec) {
}

FolderEncoder::FolderEncoder(FolderEncoder&& other) noexcept = default;

FolderEncoder& FolderEncoder::operator=(FolderEncoder&& other) noexcept = default;

FolderEncoder::~FolderEncoder() = default;

Result<FolderEncoder> FolderEncoder::create(Codec codec, int level, std::vector<std::byte>& props) {
    if (codec == Codec::Copy) {
        return FolderEncoder(std::make_unique<State>(), codec);
    }
    if (codec == Codec::Deflate) {
        auto encoder = DeflateEncoder::create(level);
        if (!encoder) {
            return std::unexpected(encoder.error());
        }
        auto state = std::make_unique<State>();
        state->deflate.emplace(std::move(*encoder));
        state->output.resize(std::size_t{256} * 1024);
        return FolderEncoder(std::move(state), codec);
    }

    if (codec == Codec::Bzip2) {
        if (level < 1 || level > 9) {
            return fail(ErrorKind::Unsupported, "7z bzip2 compression level out of range");
        }
        auto state = std::make_unique<State>();
        int status = BZ2_bzCompressInit(&state->bzip2, level, 0, 0);
        if (status != BZ_OK) {
            return fail(ErrorKind::LimitExceeded, "7z bzip2 encoder allocation failed");
        }
        state->bzip2Ready = true;
        state->output.resize(std::size_t{256} * 1024);
        return FolderEncoder(std::move(state), codec);
    }

    if (level < 0 || level > 9) {
        return fail(ErrorKind::Unsupported, "7z lzma compression level out of range");
    }

    lzma_options_lzma options;
    if (lzma_lzma_preset(&options, static_cast<std::uint32_t>(level)) != LZMA_OK) {
        return fail(ErrorKind::Unsupported, "7z lzma compression level out of range");
    }

    auto state = std::make_unique<State>();
    lzma_filter filters[2] = {};
    if (codec == Codec::Lzma1) {
        if (lzma1DictBytes < lzma1MinDictBytes) {
            return fail(ErrorKind::Malformed, "7z LZMA1 dictionary is too small");
        }
        options.dict_size = static_cast<std::uint32_t>(lzma1DictBytes);
        options.lc = lzma1LiteralContext;
        options.lp = lzma1LiteralPosition;
        options.pb = lzma1PositionBits;
        filters[0].id = LZMA_FILTER_LZMA1;

        std::uint8_t first = static_cast<std::uint8_t>(
            (lzma1PositionBits * 5 + lzma1LiteralPosition) * 9 + lzma1LiteralContext
        );
        props.push_back(static_cast<std::byte>(first));
        std::array<std::byte, 4> dict{};
        storeLe(dict.data(), static_cast<std::uint32_t>(lzma1DictBytes));
        props.insert(props.end(), dict.begin(), dict.end());
    } else {
        options.dict_size = static_cast<std::uint32_t>(lzma2DictBytes);
        filters[0].id = LZMA_FILTER_LZMA2;
        props.push_back(static_cast<std::byte>(lzma2PropsByte(lzma2DictBytes)));
    }
    filters[0].options = &options;
    filters[1].id = LZMA_VLI_UNKNOWN;

    if (lzma_raw_encoder(&state->lzma, filters) != LZMA_OK) {
        return fail(ErrorKind::Malformed, "7z lzma encoder initialization failed");
    }
    state->lzmaReady = true;
    state->output.resize(std::size_t{256} * 1024);
    return FolderEncoder(std::move(state), codec);
}

namespace {

Result<void> supplyDeflate(
    FolderEncoder::State& state,
    std::span<const std::byte> data,
    bool finish,
    const PackedSink& sink
) {
    if (!state.deflate) {
        return fail(ErrorKind::Malformed, "7z deflate encoder is missing");
    }
    auto flush = finish ? EncodeFlush::Finish : EncodeFlush::None;
    while (true) {
        auto step = state.deflate->stream(data, state.output, flush);
        if (!step) {
            return std::unexpected(step.error());
        }
        data = data.subspan(step->consumed);
        if (step->produced != 0) {
            auto wrote = sink(std::span(state.output).first(step->produced));
            if (!wrote) {
                return wrote;
            }
        }
        if (finish ? step->finished : data.empty()) {
            return {};
        }
    }
}

Result<void> supplyLzma(
    FolderEncoder::State& state,
    std::span<const std::byte> data,
    bool finish,
    const PackedSink& sink
) {
    while (!data.empty()) {
        auto chunk = data.first(std::min(data.size(), maxStepBytes));
        state.lzma.next_in = reinterpret_cast<const std::uint8_t*>(chunk.data());
        state.lzma.avail_in = chunk.size();
        state.lzma.next_out = reinterpret_cast<std::uint8_t*>(state.output.data());
        state.lzma.avail_out = state.output.size();

        auto status = lzma_code(&state.lzma, LZMA_RUN);
        std::size_t consumed = chunk.size() - state.lzma.avail_in;
        std::size_t produced = state.output.size() - state.lzma.avail_out;
        state.lzma.next_in = nullptr;
        state.lzma.avail_in = 0;
        state.lzma.next_out = nullptr;
        state.lzma.avail_out = 0;
        data = data.subspan(consumed);

        if (status == LZMA_STREAM_END) {
            state.ended = true;
            if (produced != 0) {
                auto wrote = sink(std::span(state.output).first(produced));
                if (!wrote) {
                    return wrote;
                }
            }
            if (!data.empty() || !finish) {
                return fail(ErrorKind::Malformed, "7z lzma encoder finished early");
            }
            return {};
        }
        if (status != LZMA_OK) {
            return lzmaEncodeFailure(status);
        }
        if (produced != 0) {
            auto wrote = sink(std::span(state.output).first(produced));
            if (!wrote) {
                return wrote;
            }
        }
        if (consumed == 0 && produced == 0) {
            return fail(ErrorKind::Malformed, "7z lzma encoder made no progress");
        }
    }

    if (!finish) {
        return {};
    }
    while (!state.ended) {
        state.lzma.next_in = nullptr;
        state.lzma.avail_in = 0;
        state.lzma.next_out = reinterpret_cast<std::uint8_t*>(state.output.data());
        state.lzma.avail_out = state.output.size();

        auto status = lzma_code(&state.lzma, LZMA_FINISH);
        std::size_t produced = state.output.size() - state.lzma.avail_out;
        state.lzma.next_out = nullptr;
        state.lzma.avail_out = 0;

        if (produced != 0) {
            auto wrote = sink(std::span(state.output).first(produced));
            if (!wrote) {
                return wrote;
            }
        }
        if (status == LZMA_STREAM_END) {
            state.ended = true;
            return {};
        }
        if (status != LZMA_OK) {
            return lzmaEncodeFailure(status);
        }
    }
    return {};
}

Result<void> supplyBzip2(
    FolderEncoder::State& state,
    std::span<const std::byte> data,
    bool finish,
    const PackedSink& sink
) {
    while (!data.empty()) {
        auto take = std::min<std::uint64_t>(data.size(), std::numeric_limits<unsigned int>::max());
        state.bzip2.next_in = reinterpret_cast<char*>(const_cast<std::byte*>(data.data()));
        state.bzip2.avail_in = static_cast<unsigned int>(take);
        state.bzip2.next_out = reinterpret_cast<char*>(state.output.data());
        state.bzip2.avail_out = static_cast<unsigned int>(state.output.size());

        int status = BZ2_bzCompress(&state.bzip2, BZ_RUN);
        std::size_t consumed = static_cast<std::size_t>(take) - state.bzip2.avail_in;
        std::size_t produced = state.output.size() - state.bzip2.avail_out;
        state.bzip2.next_in = nullptr;
        state.bzip2.avail_in = 0;
        state.bzip2.next_out = nullptr;
        state.bzip2.avail_out = 0;
        data = data.subspan(consumed);

        if (status != BZ_RUN_OK) {
            return fail(ErrorKind::Malformed, "7z bzip2 compression failed");
        }
        if (produced != 0) {
            auto wrote = sink(std::span(state.output).first(produced));
            if (!wrote) {
                return wrote;
            }
        }
        if (consumed == 0 && produced == 0) {
            return fail(ErrorKind::Malformed, "7z bzip2 encoder made no progress");
        }
    }

    if (!finish) {
        return {};
    }
    while (!state.ended) {
        state.bzip2.next_in = nullptr;
        state.bzip2.avail_in = 0;
        state.bzip2.next_out = reinterpret_cast<char*>(state.output.data());
        state.bzip2.avail_out = static_cast<unsigned int>(state.output.size());

        int status = BZ2_bzCompress(&state.bzip2, BZ_FINISH);
        std::size_t produced = state.output.size() - state.bzip2.avail_out;
        state.bzip2.next_out = nullptr;
        state.bzip2.avail_out = 0;

        if (produced != 0) {
            auto wrote = sink(std::span(state.output).first(produced));
            if (!wrote) {
                return wrote;
            }
        }
        if (status == BZ_STREAM_END) {
            state.ended = true;
            return {};
        }
        if (status != BZ_FINISH_OK) {
            return fail(ErrorKind::Malformed, "7z bzip2 compression failed");
        }
    }
    return {};
}

}

Result<void>
FolderEncoder::supply(std::span<const std::byte> data, bool finish, const PackedSink& sink) {
    if (state_->ended) {
        return fail(ErrorKind::Malformed, "7z folder encoder already finished");
    }
    if (codec_ == Codec::Copy) {
        if (finish) {
            state_->ended = true;
        }
        if (data.empty()) {
            return {};
        }
        return sink(data);
    }
    if (codec_ == Codec::Deflate) {
        auto done = supplyDeflate(*state_, data, finish, sink);
        if (!done) {
            return done;
        }
        if (finish) {
            state_->ended = true;
        }
        return {};
    }
    if (codec_ == Codec::Bzip2) {
        return supplyBzip2(*state_, data, finish, sink);
    }
    return supplyLzma(*state_, data, finish, sink);
}

}
