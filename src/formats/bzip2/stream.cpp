#include "formats/bzip2/stream.hpp"

#include <algorithm>

namespace bale::bzip2 {

namespace {

constexpr std::size_t headerSize = 4;

}

bool looksLikeBzip2(std::span<const std::byte> head) {
    if (head.size() < headerSize ||
        !std::ranges::equal(streamMagic, head.first(streamMagic.size()))) {
        return false;
    }

    auto block = std::to_integer<std::uint8_t>(head[3]);
    return block >= '1' && block <= '9';
}

Result<Stream> Stream::open(File file, const Limits& limits) {
    if (limits.chunkBytes == 0) {
        return fail(ErrorKind::LimitExceeded, "bzip2 chunk size is zero");
    }

    auto decoder = Bzip2Decoder::create();
    if (!decoder) {
        return tl::unexpected<Error>(decoder.error());
    }

    auto input = FileInput::open(std::move(file), std::max(limits.chunkBytes, headerSize));
    if (!input) {
        return tl::unexpected<Error>(input.error());
    }

    auto filled = input->fill(headerSize);
    if (!filled) {
        return tl::unexpected<Error>(filled.error());
    }

    auto head = input->pending();
    if (head.size() < headerSize) {
        return fail(ErrorKind::Truncated, "bzip2 stream header truncated", 0);
    }
    if (!looksLikeBzip2(head)) {
        return fail(ErrorKind::Malformed, "not a bzip2 stream", 0);
    }
    return Stream(std::move(*input), limits, std::move(*decoder));
}

Result<std::size_t> Stream::read(std::span<std::byte> out) {
    if (failure_) {
        return tl::unexpected<Error>(*failure_);
    }
    if (out.empty()) {
        return fail(ErrorKind::LimitExceeded, "bzip2 read buffer is empty");
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
                return tl::unexpected<Error>(another.error());
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
                return tl::unexpected<Error>(filled.error());
            }
            if (input_.exhausted()) {
                return fail(ErrorKind::Truncated, "bzip2 stream truncated", input_.offset());
            }
        }

        auto budget = limits_.maxOutputBytes - outputBytes_;
        auto window = budget == 0
            ? out.first(1)
            : out.first(static_cast<std::size_t>(std::min<std::uint64_t>(budget, out.size())));
        auto offset = input_.offset();
        auto step = decoder_.decompress(input_.pending(), window);
        if (!step) {
            auto error = step.error();
            error.offset = offset;
            return tl::unexpected<Error>(error);
        }

        input_.consume(step->consumed);
        if (step->produced > budget) {
            return fail(ErrorKind::LimitExceeded, "bzip2 output exceeds limit", offset);
        }

        if (step->consumed == 0 && step->produced == 0) {
            return fail(ErrorKind::Malformed, "bzip2 decoder made no progress", offset);
        }

        if (step->produced > 0) {
            outputBytes_ += step->produced;
            return step->produced;
        }
    }
}

// NOTE: concatenated streams follow the first with no separator; zero bytes between or
// after them are padding, anything else must open with the bzip2 magic.
Result<bool> Stream::beginStream() {
    while (true) {
        if (input_.pending().empty()) {
            auto filled = input_.fill(1);
            if (!filled) {
                return tl::unexpected<Error>(filled.error());
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

    auto filled = input_.fill(headerSize);
    if (!filled) {
        return tl::unexpected<Error>(filled.error());
    }

    auto head = input_.pending();
    if (head.size() < headerSize) {
        bool prefix = head.size() <= streamMagic.size()
            ? std::ranges::equal(head, std::span(streamMagic).first(head.size()))
            : head.size() >= streamMagic.size() &&
                std::ranges::equal(streamMagic, head.first(streamMagic.size()));
        if (!prefix) {
            return fail(ErrorKind::Malformed, "trailing data after bzip2 stream", input_.offset());
        }
        return fail(ErrorKind::Truncated, "bzip2 stream truncated", input_.offset());
    }
    if (!looksLikeBzip2(head)) {
        return fail(ErrorKind::Malformed, "trailing data after bzip2 stream", input_.offset());
    }

    auto reset = decoder_.reset();
    if (!reset) {
        return tl::unexpected<Error>(reset.error());
    }
    return true;
}

}
