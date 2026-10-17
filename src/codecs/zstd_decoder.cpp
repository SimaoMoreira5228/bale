#include "codecs/decoders.hpp"

#include <utility>

#include <zstd.h>
#include <zstd_errors.h>

namespace bale {

namespace {

std::unexpected<Error> zstdFailure(std::size_t code) {
    switch (ZSTD_getErrorCode(code)) {
    case ZSTD_error_frameParameter_windowTooLarge:
        return fail(ErrorKind::LimitExceeded, "zstd frame window exceeds limit");
    case ZSTD_error_memory_allocation:
        return fail(ErrorKind::LimitExceeded, "zstd decoder allocation failed");
    case ZSTD_error_checksum_wrong:
        return fail(ErrorKind::Integrity, "zstd content checksum mismatch");
    case ZSTD_error_prefix_unknown:
        return fail(ErrorKind::Malformed, "not a zstd frame");
    case ZSTD_error_dictionary_wrong:
        return fail(ErrorKind::Unsupported, "zstd frame requires a dictionary");
    default:
        return fail(ErrorKind::Malformed, "invalid zstd stream");
    }
}

}

struct ZstdDecoder::State {
    State() = default;
    State(const State&) = delete;
    State& operator=(const State&) = delete;

    ~State() {
        ZSTD_freeDCtx(context);
    }

    ZSTD_DCtx* context = nullptr;
};

ZstdDecoder::ZstdDecoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

ZstdDecoder::ZstdDecoder(ZstdDecoder&& other) noexcept = default;

ZstdDecoder& ZstdDecoder::operator=(ZstdDecoder&& other) noexcept = default;

ZstdDecoder::~ZstdDecoder() = default;

Result<ZstdDecoder> ZstdDecoder::create(const ZstdLimits& limits) {
    auto bounds = ZSTD_dParam_getBounds(ZSTD_d_windowLogMax);
    if (ZSTD_isError(bounds.error) || std::cmp_less(limits.maxWindowLog, bounds.lowerBound) ||
        std::cmp_greater(limits.maxWindowLog, bounds.upperBound)) {
        return fail(ErrorKind::Unsupported, "zstd window limit out of range");
    }

    auto state = std::make_unique<State>();
    state->context = ZSTD_createDCtx();
    if (state->context == nullptr) {
        return fail(ErrorKind::LimitExceeded, "zstd decoder allocation failed");
    }

    auto set = ZSTD_DCtx_setParameter(
        state->context,
        ZSTD_d_windowLogMax,
        static_cast<int>(limits.maxWindowLog)
    );
    if (ZSTD_isError(set)) {
        return fail(ErrorKind::Unsupported, "zstd window limit out of range");
    }
    return ZstdDecoder(std::move(state));
}

Result<DecodeStep>
ZstdDecoder::decompress(std::span<const std::byte> input, std::span<std::byte> output) {
    ZSTD_inBuffer in{
        .src = input.data(),
        .size = input.size(),
        .pos = 0,
    };
    ZSTD_outBuffer out{
        .dst = output.data(),
        .size = output.size(),
        .pos = 0,
    };

    auto hint = ZSTD_decompressStream(state_->context, &out, &in);
    if (ZSTD_isError(hint)) {
        return zstdFailure(hint);
    }

    return DecodeStep{
        .consumed = in.pos,
        .produced = out.pos,
        .finished = hint == 0,
    };
}

Result<void> ZstdDecoder::reset() {
    auto status = ZSTD_DCtx_reset(state_->context, ZSTD_reset_session_only);
    if (ZSTD_isError(status)) {
        return fail(ErrorKind::Malformed, "zstd decoder reset failed");
    }
    return {};
}

}
