#include "formats/xz/stream.hpp"

#include "base/endian.hpp"

#include <algorithm>

namespace bale::xz {

bool looksLikeXz(std::span<const std::byte> head) {
    return std::ranges::starts_with(head, streamMagic);
}

Result<Stream> Stream::open(File file, const Limits& limits) {
    if (limits.chunkBytes == 0) {
        return fail(ErrorKind::LimitExceeded, "xz chunk size is zero");
    }

    auto decoder = XzDecoder::create({.memLimitBytes = limits.memLimitBytes});
    if (!decoder) {
        return std::unexpected(decoder.error());
    }

    auto input = FileInput::open(std::move(file), std::max(limits.chunkBytes, streamMagic.size()));
    if (!input) {
        return std::unexpected(input.error());
    }

    auto filled = input->fill(streamMagic.size());
    if (!filled) {
        return std::unexpected(filled.error());
    }

    auto head = input->pending();
    if (head.size() < streamMagic.size()) {
        return fail(ErrorKind::Truncated, "xz stream header truncated", 0);
    }
    if (!looksLikeXz(head)) {
        return fail(ErrorKind::Malformed, "not an xz stream", 0);
    }
    return Stream(std::move(*input), limits, std::move(*decoder));
}

Result<std::size_t> Stream::read(std::span<std::byte> out) {
    if (failure_) {
        return std::unexpected(*failure_);
    }
    if (out.empty()) {
        return fail(ErrorKind::LimitExceeded, "xz read buffer is empty");
    }

    auto produced = decode(out);
    if (!produced) {
        failure_ = produced.error();
    }
    return produced;
}

Result<std::size_t> Stream::decode(std::span<std::byte> out) {
    while (true) {
        if (decoder_.streamEnded()) {
            auto another = beginStream();
            if (!another) {
                return std::unexpected(another.error());
            }
            if (!*another) {
                return 0;
            }
            ++streams_;
            continue;
        }

        if (input_.pending().empty()) {
            auto filled = input_.fill(1);
            if (!filled) {
                return std::unexpected(filled.error());
            }
        }

        bool flushing = input_.pending().empty();
        auto budget = limits_.maxOutputBytes - outputBytes_;
        auto window = budget == 0
            ? out.first(1)
            : out.first(static_cast<std::size_t>(std::min<std::uint64_t>(budget, out.size())));
        auto offset = input_.offset();
        auto step = decoder_.decompress(input_.pending(), window, flushing);
        if (!step) {
            auto error = step.error();
            error.offset = offset;
            return std::unexpected(error);
        }

        input_.consume(step->consumed);
        if (step->produced > budget) {
            return fail(ErrorKind::LimitExceeded, "xz output exceeds limit", offset);
        }

        if (step->produced > 0) {
            outputBytes_ += step->produced;
            return step->produced;
        }
        if (step->finished) {
            continue;
        }
        if (step->consumed == 0) {
            if (flushing) {
                return fail(ErrorKind::Truncated, "xz stream truncated", offset);
            }
            return fail(ErrorKind::Malformed, "xz decoder made no progress", offset);
        }
    }
}

// NOTE: concatenated streams follow the first with no separator; zero bytes between or
// after them are padding, anything else must open with the xz magic.
Result<bool> Stream::beginStream() {
    while (true) {
        if (input_.pending().empty()) {
            auto filled = input_.fill(1);
            if (!filled) {
                return std::unexpected(filled.error());
            }
            if (input_.exhausted()) {
                return false;
            }
        }

        if (input_.pending().front() != std::byte{0}) {
            break;
        }
        input_.consume(1);
    }

    auto filled = input_.fill(streamMagic.size());
    if (!filled) {
        return std::unexpected(filled.error());
    }

    auto head = input_.pending();
    if (head.size() < streamMagic.size()) {
        if (!std::ranges::starts_with(streamMagic, head)) {
            return fail(ErrorKind::Malformed, "trailing data after xz stream", input_.offset());
        }
        return fail(ErrorKind::Truncated, "xz stream truncated", input_.offset());
    }
    if (!looksLikeXz(head)) {
        return fail(ErrorKind::Malformed, "trailing data after xz stream", input_.offset());
    }

    auto reset = decoder_.reset();
    if (!reset) {
        return std::unexpected(reset.error());
    }
    return true;
}

}
