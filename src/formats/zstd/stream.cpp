#include "formats/zstd/stream.hpp"

#include "base/endian.hpp"

#include <algorithm>

namespace bale::zstd {

namespace {

constexpr std::uint32_t skippableMagicMask = 0xFFFFFFF0;
constexpr std::uint32_t skippableMagic = 0x184D2A50;

}

bool looksLikeZstd(std::span<const std::byte> head) {
    return std::ranges::starts_with(head, frameMagic);
}

Result<Stream> Stream::open(File file, const Limits& limits) {
    if (limits.chunkBytes == 0) {
        return fail(ErrorKind::LimitExceeded, "zstd chunk size is zero");
    }

    auto decoder = ZstdDecoder::create({.maxWindowLog = limits.maxWindowLog});
    if (!decoder) {
        return std::unexpected(decoder.error());
    }

    auto input = FileInput::open(std::move(file), std::max(limits.chunkBytes, frameMagic.size()));
    if (!input) {
        return std::unexpected(input.error());
    }

    auto filled = input->fill(frameMagic.size());
    if (!filled) {
        return std::unexpected(filled.error());
    }

    auto head = input->pending();
    if (head.size() < frameMagic.size()) {
        return fail(ErrorKind::Truncated, "zstd frame header truncated", 0);
    }
    auto magic = loadLe<std::uint32_t>(head.data());
    if (!looksLikeZstd(head) && (magic & skippableMagicMask) != skippableMagic) {
        return fail(ErrorKind::Malformed, "not a zstd frame", 0);
    }
    return Stream(std::move(*input), limits, std::move(*decoder));
}

Result<std::size_t> Stream::read(std::span<std::byte> out) {
    if (failure_) {
        return std::unexpected(*failure_);
    }
    if (out.empty()) {
        return fail(ErrorKind::LimitExceeded, "zstd read buffer is empty");
    }

    auto produced = decode(out);
    if (!produced) {
        failure_ = produced.error();
    }
    return produced;
}

Result<std::size_t> Stream::decode(std::span<std::byte> out) {
    while (true) {
        if (input_.pending().empty()) {
            auto filled = input_.fill(1);
            if (!filled) {
                return std::unexpected(filled.error());
            }
        }

        bool flushing = input_.pending().empty();
        if (flushing && frameEnded_) {
            return 0;
        }

        // SECURITY: an exhausted budget leaves a one-byte probe window whose output is never passed
        // on, so a bomb stops after a single byte past the limit.
        auto budget = limits_.maxOutputBytes - outputBytes_;
        auto window = budget == 0
            ? out.first(1)
            : out.first(static_cast<std::size_t>(std::min<std::uint64_t>(budget, out.size())));
        auto offset = input_.offset();
        auto step = decoder_.decompress(input_.pending(), window);
        if (!step) {
            auto error = step.error();
            error.offset = offset;
            return std::unexpected(error);
        }

        input_.consume(step->consumed);
        if (step->produced > budget) {
            return fail(ErrorKind::LimitExceeded, "zstd output exceeds limit", offset);
        }

        if (step->consumed == 0 && step->produced == 0) {
            if (flushing) {
                return fail(ErrorKind::Truncated, "zstd stream truncated", offset);
            }
            return fail(ErrorKind::Malformed, "zstd decoder made no progress", offset);
        }

        frameEnded_ = step->finished;
        if (step->produced > 0) {
            outputBytes_ += step->produced;
            return step->produced;
        }
    }
}

}
