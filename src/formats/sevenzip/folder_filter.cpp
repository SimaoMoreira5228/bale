#include "formats/sevenzip/folder.hpp"

#include <algorithm>

namespace bale::sevenzip {

Result<std::span<const std::byte>> FolderSession::nextFiltered() {
    if (plan_.codec.codec != Codec::Bcj && plan_.codec.codec != Codec::Copy) {
        return nextCodedFiltered();
    }

    while (true) {
        if (entryLeft_ == 0) {
            auto finished = finishEntry();
            if (!finished) {
                return tl::unexpected<Error>(finished.error());
            }
            return std::span<const std::byte>{};
        }

        if (pending_.empty()) {
            auto filled = fillInput();
            if (!filled) {
                return tl::unexpected<Error>(filled.error());
            }
        }

        std::uint64_t windowSize =
            std::min(static_cast<std::uint64_t>(output_.size()), entryEnd_ - unpackPosition_);
        if (windowSize == 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }
        auto window = output_.first(static_cast<std::size_t>(windowSize));

        if (!pending_.empty()) {
            auto step = bcj_.filter(pending_, window);
            if (!step) {
                auto error = step.error();
                error.offset = packPosition_;
                pending_ = {};
                return tl::unexpected<Error>(error);
            }

            auto consumed = noteConsumed(step->consumed);
            if (!consumed) {
                pending_ = {};
                return tl::unexpected<Error>(consumed.error());
            }

            if (step->produced > 0) {
                auto part = deliver(window.first(step->produced));
                if (!part) {
                    return tl::unexpected<Error>(part.error());
                }
                if (!part->empty()) {
                    return *part;
                }
                continue;
            }
        }

        if (pending_.empty() && packPosition_ >= packDataEnd_) {
            auto flushed = bcj_.flush(window);
            if (!flushed) {
                return tl::unexpected<Error>(flushed.error());
            }
            if (*flushed == 0) {
                return fail(ErrorKind::Truncated, "7z data stream truncated", packPosition_);
            }
            auto part = deliver(window.first(*flushed));
            if (!part) {
                return tl::unexpected<Error>(part.error());
            }
            if (!part->empty()) {
                return *part;
            }
            continue;
        }

        if (pending_.empty()) {
            continue;
        }
        return fail(ErrorKind::Malformed, "7z filter made no progress", packPosition_);
    }
}

Result<std::span<const std::byte>> FolderSession::nextCodedFiltered() {
    while (true) {
        if (entryLeft_ == 0) {
            auto finished = finishEntry();
            if (!finished) {
                return tl::unexpected<Error>(finished.error());
            }
            return std::span<const std::byte>{};
        }

        if (pending_.empty() && packPosition_ < packDataEnd_) {
            auto filled = fillInput();
            if (!filled) {
                return tl::unexpected<Error>(filled.error());
            }
        }

        if (!decoderFinished_) {
            Result<DecodeStep> result = DecodeStep{};
            if (auto* inflater = std::get_if<Inflater*>(&decoder_)) {
                result = (*inflater)->decompress(pending_, output_);
            } else if (auto* bzip2 = std::get_if<Bzip2Decoder*>(&decoder_)) {
                result = (*bzip2)->decompress(pending_, output_);
            } else if (auto* lzma = std::get_if<RawLzma>(&decoder_)) {
                result = lzma->decompress(pending_, output_);
            } else {
                return fail(ErrorKind::Malformed, "7z decoder is missing", packPosition_);
            }
            if (!result) {
                auto error = result.error();
                error.offset = packPosition_;
                pending_ = {};
                return tl::unexpected<Error>(error);
            }

            auto consumed = noteConsumed(result->consumed);
            if (!consumed) {
                pending_ = {};
                return tl::unexpected<Error>(consumed.error());
            }
            decoderFinished_ = result->finished;

            if (result->finished && (!pending_.empty() || packPosition_ < packDataEnd_)) {
                return fail(ErrorKind::Malformed, "7z filtered stream has trailing packed data");
            }

            if (result->produced > 0) {
                std::uint64_t windowSize = std::min(
                    static_cast<std::uint64_t>(filterOutput_.size()),
                    entryEnd_ - unpackPosition_
                );
                if (windowSize == 0) {
                    return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
                }
                auto window = filterOutput_.first(static_cast<std::size_t>(windowSize));
                auto step = bcj_.filter(output_.first(result->produced), window);
                if (!step) {
                    auto error = step.error();
                    error.offset = packPosition_;
                    return tl::unexpected<Error>(error);
                }
                if (step->consumed != result->produced) {
                    return fail(ErrorKind::Malformed, "7z BCJ filter did not consume its input");
                }
                if (step->produced > 0) {
                    auto part = deliver(window.first(step->produced));
                    if (!part) {
                        return tl::unexpected<Error>(part.error());
                    }
                    if (!part->empty()) {
                        return *part;
                    }
                }
                continue;
            }

            if (!result->finished && result->consumed == 0) {
                if (pending_.empty() && packPosition_ >= packDataEnd_) {
                    return fail(ErrorKind::Truncated, "7z data stream truncated", packPosition_);
                }
                return fail(ErrorKind::Malformed, "7z decoder made no progress", packPosition_);
            }
            continue;
        }

        if (pending_.empty() && packPosition_ >= packDataEnd_) {
            std::uint64_t windowSize = std::min(
                static_cast<std::uint64_t>(filterOutput_.size()),
                entryEnd_ - unpackPosition_
            );
            if (windowSize == 0) {
                return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
            }
            auto window = filterOutput_.first(static_cast<std::size_t>(windowSize));
            auto flushed = bcj_.flush(window);
            if (!flushed) {
                return tl::unexpected<Error>(flushed.error());
            }
            if (*flushed == 0) {
                return fail(ErrorKind::Truncated, "7z data stream truncated", packPosition_);
            }
            auto part = deliver(window.first(*flushed));
            if (!part) {
                return tl::unexpected<Error>(part.error());
            }
            if (!part->empty()) {
                return *part;
            }
            continue;
        }

        return fail(ErrorKind::Malformed, "7z filtered stream has trailing packed data");
    }
}

}
