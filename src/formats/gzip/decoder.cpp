#include "formats/gzip/decoder.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <algorithm>
#include <array>

namespace bale::gzip {

Result<Decoder> Decoder::open(File file, const Limits& limits) {
    if (limits.chunkBytes == 0) {
        return fail(ErrorKind::LimitExceeded, "gzip chunk size is zero");
    }

    auto headerLimit = maxHeaderSize(limits);
    if (!headerLimit) {
        return std::unexpected(headerLimit.error());
    }

    auto fileSize = file.size();
    if (!fileSize) {
        return std::unexpected(fileSize.error());
    }
    if (*fileSize < fixedHeaderSize) {
        return fail(ErrorKind::Truncated, "gzip header truncated", 0);
    }

    auto inflater = Inflater::create();
    if (!inflater) {
        return std::unexpected(inflater.error());
    }

    auto inputSize = static_cast<std::size_t>(
        std::min<std::uint64_t>(std::max(limits.chunkBytes, *headerLimit), *fileSize)
    );
    auto bufferSize = checkedAdd(inputSize, limits.chunkBytes);
    if (!bufferSize) {
        return fail(ErrorKind::LimitExceeded, "gzip chunk size too large");
    }

    Decoder decoder(std::move(file), *fileSize, limits, std::move(*inflater));
    decoder.buffer_.resize(*bufferSize);
    decoder.input_ = std::span(decoder.buffer_).first(inputSize);
    decoder.output_ = std::span(decoder.buffer_).subspan(inputSize);

    auto first = decoder.startMember(0);
    if (!first) {
        return std::unexpected(first.error());
    }

    auto raw = decoder.input_.first(first->size);
    decoder.firstHeader_.assign(raw.begin(), raw.end());
    auto header = parseHeader(decoder.firstHeader_, limits);
    if (!header) {
        return std::unexpected(header.error());
    }
    decoder.header_ = *header;
    return decoder;
}

Result<Header> Decoder::startMember(std::uint64_t offset) {
    auto window = input_.first(
        static_cast<std::size_t>(std::min<std::uint64_t>(input_.size(), fileSize_ - offset))
    );
    auto read = file_.readExactAt(offset, window);
    if (!read) {
        return std::unexpected(read.error());
    }

    auto header = parseHeader(window, limits_, offset);
    if (!header) {
        return std::unexpected(header.error());
    }

    auto reset = inflater_.reset();
    if (!reset) {
        return std::unexpected(reset.error());
    }

    pending_ = window.subspan(header->size);
    position_ = offset + window.size();
    memberStart_ = offset;
    memberBytes_ = 0;
    crc_ = {};
    streamEnded_ = false;
    return header;
}

Result<std::span<const std::byte>> Decoder::nextChunk() {
    while (!done_) {
        if (streamEnded_) {
            auto another = finishMember();
            if (!another) {
                return std::unexpected(another.error());
            }
            if (!*another) {
                done_ = true;
                break;
            }
            ++summary_.members;
            continue;
        }

        if (pending_.empty() && position_ < fileSize_) {
            auto chunk = input_.first(
                static_cast<std::size_t>(
                    std::min<std::uint64_t>(input_.size(), fileSize_ - position_)
                )
            );
            auto read = file_.readExactAt(position_, chunk);
            if (!read) {
                return std::unexpected(read.error());
            }

            pending_ = chunk;
            position_ += chunk.size();
        }

        // SECURITY: an exhausted budget leaves a one-byte probe window whose output is never passed
        // on, so a bomb stops after a single byte past the limit.
        auto budget = limits_.maxOutputBytes - summary_.outputBytes;
        auto window = budget == 0
            ? output_.first(1)
            : output_.first(
                  static_cast<std::size_t>(std::min<std::uint64_t>(budget, output_.size()))
              );
        auto step = inflater_.decompress(pending_, window);
        if (!step) {
            auto error = step.error();
            error.offset = memberStart_;
            return std::unexpected(error);
        }

        pending_ = pending_.subspan(step->consumed);
        if (step->produced > budget) {
            return fail(ErrorKind::LimitExceeded, "gzip output exceeds limit", memberStart_);
        }

        streamEnded_ = step->finished;
        if (step->produced > 0) {
            auto chunk = window.first(step->produced);
            crc_.update(chunk);
            memberBytes_ += chunk.size();
            summary_.outputBytes += chunk.size();
            return std::span<const std::byte>(chunk);
        }
        if (step->finished) {
            continue;
        }
        if (step->consumed == 0) {
            if (pending_.empty() && position_ == fileSize_) {
                return fail(ErrorKind::Truncated, "deflate stream truncated", memberStart_);
            }
            return fail(ErrorKind::Malformed, "deflate decoder made no progress", memberStart_);
        }
    }
    return std::span<const std::byte>{};
}

Result<bool> Decoder::finishMember() {
    auto end = position_ - pending_.size();
    if (fileSize_ - end < trailerSize) {
        return fail(ErrorKind::Truncated, "gzip trailer truncated", end);
    }

    std::array<std::byte, trailerSize> trailer{};
    auto read = file_.readExactAt(end, trailer);
    if (!read) {
        return std::unexpected(read.error());
    }
    if (loadLe<std::uint32_t>(trailer.data()) != crc_.value()) {
        return fail(ErrorKind::Integrity, "gzip member CRC-32 mismatch", end);
    }
    if (loadLe<std::uint32_t>(trailer.data() + 4) != static_cast<std::uint32_t>(memberBytes_)) {
        return fail(ErrorKind::Integrity, "gzip member size mismatch", end);
    }

    auto next = end + trailerSize;
    if (next == fileSize_) {
        return false;
    }

    std::array<std::byte, 1> lead{};
    auto leadRead = file_.readExactAt(next, lead);
    if (!leadRead) {
        return std::unexpected(leadRead.error());
    }
    if (lead[0] == std::byte{0}) {
        auto padding = checkPadding(next);
        if (!padding) {
            return std::unexpected(padding.error());
        }
        return false;
    }
    if (lead[0] != std::byte{0x1f}) {
        return fail(ErrorKind::Malformed, "trailing garbage after gzip member", next);
    }

    auto header = startMember(next);
    if (!header) {
        return std::unexpected(header.error());
    }
    return true;
}

Result<void> Decoder::checkPadding(std::uint64_t offset) {
    while (offset < fileSize_) {
        auto chunk = input_.first(
            static_cast<std::size_t>(std::min<std::uint64_t>(input_.size(), fileSize_ - offset))
        );
        auto read = file_.readExactAt(offset, chunk);
        if (!read) {
            return read;
        }

        auto nonZero = std::ranges::find_if(chunk, [](std::byte value) {
            return value != std::byte{0};
        });
        if (nonZero != chunk.end()) {
            return fail(
                ErrorKind::Malformed,
                "trailing garbage after gzip member",
                offset + static_cast<std::uint64_t>(nonZero - chunk.begin())
            );
        }
        offset += chunk.size();
    }
    return {};
}

}
