#include "formats/gzip/stream.hpp"

#include "base/endian.hpp"

#include <algorithm>

namespace bale::gzip {

Result<Stream> Stream::open(File file, const Limits& limits) {
    if (limits.chunkBytes == 0) {
        return fail(ErrorKind::LimitExceeded, "gzip chunk size is zero");
    }

    auto headerLimit = maxHeaderSize(limits);
    if (!headerLimit) {
        return std::unexpected(headerLimit.error());
    }

    auto inflater = Inflater::create();
    if (!inflater) {
        return std::unexpected(inflater.error());
    }

    auto input = FileInput::open(std::move(file), std::max(limits.chunkBytes, *headerLimit));
    if (!input) {
        return std::unexpected(input.error());
    }

    Stream stream(std::move(*input), limits, *headerLimit, std::move(*inflater));
    auto first = stream.beginMember();
    if (!first) {
        return std::unexpected(first.error());
    }

    auto raw = stream.input_.pending().first(first->size);
    stream.firstHeader_.assign(raw.begin(), raw.end());
    stream.input_.consume(first->size);

    auto header = parseHeader(stream.firstHeader_, limits);
    if (!header) {
        return std::unexpected(header.error());
    }
    stream.header_ = *header;
    return stream;
}

Result<std::size_t> Stream::read(std::span<std::byte> out) {
    if (failure_) {
        return std::unexpected(*failure_);
    }
    if (out.empty()) {
        return fail(ErrorKind::LimitExceeded, "gzip read buffer is empty");
    }

    auto produced = decode(out);
    if (!produced) {
        failure_ = produced.error();
    }
    return produced;
}

Result<std::size_t> Stream::decode(std::span<std::byte> out) {
    while (!done_) {
        if (memberEnded_) {
            auto another = finishMember();
            if (!another) {
                return std::unexpected(another.error());
            }
            if (!*another) {
                done_ = true;
                break;
            }
            ++members_;
            continue;
        }

        if (input_.pending().empty()) {
            auto filled = input_.fill(1);
            if (!filled) {
                return std::unexpected(filled.error());
            }
        }

        // SECURITY: an exhausted budget leaves a one-byte probe window whose output is never passed
        // on, so a bomb stops after a single byte past the limit.
        auto budget = limits_.maxOutputBytes - outputBytes_;
        auto window = budget == 0
            ? out.first(1)
            : out.first(static_cast<std::size_t>(std::min<std::uint64_t>(budget, out.size())));
        auto step = inflater_.decompress(input_.pending(), window);
        if (!step) {
            auto error = step.error();
            error.offset = memberStart_;
            return std::unexpected(error);
        }

        input_.consume(step->consumed);
        if (step->produced > budget) {
            return fail(ErrorKind::LimitExceeded, "gzip output exceeds limit", memberStart_);
        }

        memberEnded_ = step->finished;
        if (step->produced > 0) {
            auto chunk = window.first(step->produced);
            crc_.update(chunk);
            memberBytes_ += chunk.size();
            outputBytes_ += chunk.size();
            return chunk.size();
        }
        if (step->finished) {
            continue;
        }
        if (step->consumed == 0) {
            if (input_.exhausted()) {
                return fail(ErrorKind::Truncated, "deflate stream truncated", memberStart_);
            }
            return fail(ErrorKind::Malformed, "deflate decoder made no progress", memberStart_);
        }
    }
    return 0;
}

Result<Header> Stream::beginMember() {
    memberStart_ = input_.offset();
    auto filled = input_.fill(headerLimit_);
    if (!filled) {
        return std::unexpected(filled.error());
    }

    auto header = parseHeader(input_.pending(), limits_, memberStart_);
    if (!header) {
        return std::unexpected(header.error());
    }

    auto reset = inflater_.reset();
    if (!reset) {
        return std::unexpected(reset.error());
    }

    memberBytes_ = 0;
    crc_ = {};
    memberEnded_ = false;
    return header;
}

Result<bool> Stream::finishMember() {
    auto filled = input_.fill(trailerSize);
    if (!filled) {
        return std::unexpected(filled.error());
    }

    auto end = input_.offset();
    auto trailer = input_.pending();
    if (trailer.size() < trailerSize) {
        return fail(ErrorKind::Truncated, "gzip trailer truncated", end);
    }
    if (loadLe<std::uint32_t>(trailer.data()) != crc_.value()) {
        return fail(ErrorKind::Integrity, "gzip member CRC-32 mismatch", end);
    }
    if (loadLe<std::uint32_t>(trailer.data() + 4) != static_cast<std::uint32_t>(memberBytes_)) {
        return fail(ErrorKind::Integrity, "gzip member size mismatch", end);
    }
    input_.consume(trailerSize);

    auto more = input_.fill(1);
    if (!more) {
        return std::unexpected(more.error());
    }
    if (input_.exhausted()) {
        return false;
    }

    auto lead = input_.pending().front();
    if (lead == std::byte{0}) {
        auto padding = checkPadding();
        if (!padding) {
            return std::unexpected(padding.error());
        }
        return false;
    }
    if (lead != std::byte{0x1f}) {
        return fail(ErrorKind::Malformed, "trailing garbage after gzip member", input_.offset());
    }

    auto header = beginMember();
    if (!header) {
        return std::unexpected(header.error());
    }
    input_.consume(header->size);
    return true;
}

Result<void> Stream::checkPadding() {
    while (!input_.exhausted()) {
        auto filled = input_.fill(1);
        if (!filled) {
            return filled;
        }

        auto chunk = input_.pending();
        auto nonZero = std::ranges::find_if(chunk, [](std::byte value) {
            return value != std::byte{0};
        });
        if (nonZero != chunk.end()) {
            return fail(
                ErrorKind::Malformed,
                "trailing garbage after gzip member",
                input_.offset() + static_cast<std::uint64_t>(nonZero - chunk.begin())
            );
        }
        input_.consume(chunk.size());
    }
    return {};
}

}
