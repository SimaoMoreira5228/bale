#include "codecs/zstd_encoder.hpp"

#include <utility>

#include <zstd.h>
#include <zstd_errors.h>

namespace bale {

struct ZstdEncoder::State {
    ~State() {
        ZSTD_freeCCtx(context);
    }

    ZSTD_CCtx* context = nullptr;
};

ZstdEncoder::ZstdEncoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

ZstdEncoder::ZstdEncoder(ZstdEncoder&& other) noexcept = default;

ZstdEncoder& ZstdEncoder::operator=(ZstdEncoder&& other) noexcept = default;

ZstdEncoder::~ZstdEncoder() = default;

Result<ZstdEncoder> ZstdEncoder::create(int compressionLevel) {
    auto state = std::make_unique<State>();
    state->context = ZSTD_createCCtx();
    if (state->context == nullptr) {
        return fail(ErrorKind::LimitExceeded, "zstd encoder allocation failed");
    }

    auto set = ZSTD_CCtx_setParameter(state->context, ZSTD_c_compressionLevel, compressionLevel);
    if (ZSTD_isError(set)) {
        return fail(ErrorKind::Unsupported, "zstd compression level out of range");
    }
    return ZstdEncoder(std::move(state));
}

std::size_t ZstdEncoder::compressBound(std::size_t inputSize) {
    return ZSTD_compressBound(inputSize);
}

Result<std::size_t>
ZstdEncoder::compress(std::span<const std::byte> input, std::span<std::byte> output) {
    auto reset = ZSTD_CCtx_reset(state_->context, ZSTD_reset_session_only);
    if (ZSTD_isError(reset)) {
        return fail(ErrorKind::Malformed, "zstd encoder reset failed");
    }

    auto size =
        ZSTD_compress2(state_->context, output.data(), output.size(), input.data(), input.size());
    if (ZSTD_isError(size)) {
        if (ZSTD_getErrorCode(size) == ZSTD_error_dstSize_tooSmall) {
            return fail(ErrorKind::LimitExceeded, "zstd output buffer is too small");
        }
        return fail(ErrorKind::Malformed, "zstd compression failed");
    }
    return size;
}

}
