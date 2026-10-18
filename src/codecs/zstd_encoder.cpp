#include "codecs/encoders.hpp"

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

Result<ZstdEncoder> ZstdEncoder::create(int compressionLevel, bool contentChecksum) {
    auto state = std::make_unique<State>();
    state->context = ZSTD_createCCtx();
    if (state->context == nullptr) {
        return fail(ErrorKind::LimitExceeded, "zstd encoder allocation failed");
    }

    auto set = ZSTD_CCtx_setParameter(state->context, ZSTD_c_compressionLevel, compressionLevel);
    if (ZSTD_isError(set)) {
        return fail(ErrorKind::Unsupported, "zstd compression level out of range");
    }

    auto checksum =
        ZSTD_CCtx_setParameter(state->context, ZSTD_c_checksumFlag, contentChecksum ? 1 : 0);
    if (ZSTD_isError(checksum)) {
        return fail(ErrorKind::Unsupported, "zstd checksum flag rejected");
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

Result<EncodeStep> ZstdEncoder::stream(
    std::span<const std::byte> input,
    std::span<std::byte> output,
    EncodeFlush flush
) {
    ZSTD_inBuffer in{input.data(), input.size(), 0};
    ZSTD_outBuffer out{output.data(), output.size(), 0};

    ZSTD_EndDirective directive = ZSTD_e_continue;
    if (flush == EncodeFlush::Sync) {
        directive = ZSTD_e_flush;
    } else if (flush == EncodeFlush::Finish) {
        directive = ZSTD_e_end;
    }

    auto remaining = ZSTD_compressStream2(state_->context, &out, &in, directive);
    if (ZSTD_isError(remaining)) {
        return fail(ErrorKind::Malformed, "zstd compression failed");
    }

    EncodeStep step{
        .consumed = in.pos,
        .produced = out.pos,
    };
    if (flush == EncodeFlush::None) {
        step.finished = in.pos == in.size;
    } else {
        step.finished = in.pos == in.size && remaining == 0;
    }
    return step;
}

}
