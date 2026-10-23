#include "codecs/lzma2.hpp"

#include "base/checked.hpp"

#include <utility>

#include <lzma.h>

namespace bale {

namespace {

tl::unexpected<Error> lzmaEncodeFailure(lzma_ret status) {
    switch (status) {
    case LZMA_MEM_ERROR:
        return fail(ErrorKind::LimitExceeded, "lzma2 encoder allocation failed");
    case LZMA_OPTIONS_ERROR:
        return fail(ErrorKind::Unsupported, "lzma2 compression level out of range");
    case LZMA_BUF_ERROR:
        return fail(ErrorKind::LimitExceeded, "lzma2 output buffer is too small");
    default:
        return fail(ErrorKind::Malformed, "lzma2 compression failed");
    }
}

}

struct Lzma2Encoder::State {
    int compressionLevel = 6;
};

Lzma2Encoder::Lzma2Encoder(std::unique_ptr<State> state) : state_(std::move(state)) {
}

Lzma2Encoder::Lzma2Encoder(Lzma2Encoder&& other) noexcept = default;

Lzma2Encoder& Lzma2Encoder::operator=(Lzma2Encoder&& other) noexcept = default;

Lzma2Encoder::~Lzma2Encoder() = default;

Result<Lzma2Encoder> Lzma2Encoder::create(int compressionLevel) {
    if (compressionLevel < minLzma2Level || compressionLevel > maxLzma2Level) {
        return fail(ErrorKind::Unsupported, "lzma2 compression level out of range");
    }

    auto state = std::make_unique<State>();
    state->compressionLevel = compressionLevel;
    return Lzma2Encoder(std::move(state));
}

std::size_t Lzma2Encoder::compressBound(std::size_t inputSize) {
    std::size_t bound = lzma_stream_buffer_bound(inputSize);
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
Lzma2Encoder::compress(std::span<const std::byte> input, std::span<std::byte> output) {
    std::size_t outPos = 0;
    auto status = lzma_easy_buffer_encode(
        static_cast<std::uint32_t>(state_->compressionLevel),
        LZMA_CHECK_CRC32,
        nullptr,
        reinterpret_cast<const std::uint8_t*>(input.data()),
        input.size(),
        reinterpret_cast<std::uint8_t*>(output.data()),
        &outPos,
        output.size()
    );
    if (status != LZMA_OK) {
        return lzmaEncodeFailure(status);
    }
    return outPos;
}

}
