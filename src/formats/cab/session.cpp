#include "formats/cab/session.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace bale::cab {

namespace {
constexpr std::array<std::byte, 2> mszipSignature{
    std::byte{'C'},
    std::byte{'K'},
};

[[nodiscard]] std::uint32_t checksumBlock(
    std::uint64_t compressed,
    std::uint64_t uncompressed,
    std::span<const std::byte> payload
) {
    // NOTE: reverse-fit against real-world decoders with chosen-plaintext
    // probes: the header word ((cbUncomp << 16) | cbData) XORed with every
    // little-endian payload word, plus a big-endian residue.
    std::uint32_t sum =
        (static_cast<std::uint32_t>(uncompressed) << 16) | static_cast<std::uint32_t>(compressed);
    std::size_t index = 0;
    while (index + 4 <= payload.size()) {
        sum ^= loadLe<std::uint32_t>(payload.data() + index);
        index += 4;
    }
    std::uint32_t residue = 0;
    while (index < payload.size()) {
        residue = (residue << 8) | static_cast<std::uint8_t>(payload[index]);
        ++index;
    }
    return sum ^ residue;
}

}

Result<Session> Session::start(File file, const Folder& folder, Inflater* inflater) {
    Session session(std::move(file), folder, inflater);
    if (folder.method == methodLzx) {
        auto decoder = LzxDecoder::create(folder.windowBits, folder.uncompressedBytes);
        if (!decoder) {
            return std::unexpected(decoder.error());
        }
        session.lzx_.emplace(std::move(*decoder));
    }
    if (folder.method == methodMszip && inflater != nullptr) {
        if (auto reset = inflater->reset(); !reset) {
            return std::unexpected(reset.error());
        }
    }
    return session;
}

std::uint64_t Session::position() const {
    return folderPosition_;
}

Result<void>
Session::startEntry(std::uint64_t offset, std::uint64_t size, std::span<std::byte> scratch) {
    auto end = checkedAdd(offset, size);
    if (!end || *end > folder_.uncompressedBytes) {
        return fail(ErrorKind::Malformed, "cabinet entry extends past its folder");
    }

    entryBegin_ = offset;
    entryEnd_ = *end;
    entryLeft_ = size;

    if (folder_.method == methodStored) {
        input_ = scratch;
        output_ = {};
    } else {
        if (scratch.size() < 2) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer too small for cabinet decode");
        }
        input_ = scratch.first(scratch.size() / 2);
        output_ = scratch.subspan(scratch.size() / 2);
    }
    return {};
}

Result<std::span<const std::byte>> Session::nextChunk() {
    if (entryLeft_ == 0) {
        return std::span<const std::byte>{};
    }
    if (folder_.method == methodStored) {
        return nextStored();
    }
    if (folder_.method == methodMszip) {
        return nextMszip();
    }
    return nextLzx();
}

Session::Session(File file, const Folder& folder, Inflater* inflater) :
    file_(std::move(file)), folder_(folder), inflater_(inflater) {
}

Result<void> Session::loadBlock(std::size_t block) {
    const DataBlock& info = folder_.blocks[block];
    auto bytes = checkedCast<std::size_t>(info.compressedBytes);
    if (!bytes) {
        return fail(ErrorKind::LimitExceeded, "cabinet data block exceeds limit");
    }

    payload_.resize(*bytes);
    auto read = file_.readExactAt(info.payloadOffset, std::span(payload_));
    if (!read) {
        return std::unexpected(read.error());
    }

    if (info.checksum != 0) {
        std::uint32_t actual =
            checksumBlock(info.compressedBytes, info.uncompressedBytes, payload_);
        if (actual != info.checksum) {
            return fail(ErrorKind::Integrity, "cabinet data checksum mismatch", info.payloadOffset);
        }
    }
    return {};
}

Result<std::span<const std::byte>> Session::deliver(std::span<const std::byte> chunk) {
    std::uint64_t start = folderPosition_;
    auto end = checkedAdd(start, chunk.size());
    if (!end || *end > folder_.uncompressedBytes) {
        return fail(ErrorKind::Malformed, "cabinet folder data exceeds its declared size");
    }
    folderPosition_ = *end;

    if (start >= entryEnd_) {
        return fail(ErrorKind::Malformed, "cabinet decode passed its entry");
    }
    if (*end <= entryBegin_) {
        return std::span<const std::byte>{};
    }

    std::size_t skip = start < entryBegin_ ? static_cast<std::size_t>(entryBegin_ - start) : 0;
    auto part = chunk.subspan(skip);
    if (part.size() > entryLeft_) {
        part = part.first(static_cast<std::size_t>(entryLeft_));
    }
    entryLeft_ -= part.size();
    return std::span<const std::byte>(part);
}

std::uint64_t Session::entryRoom() const {
    return entryEnd_ - folderPosition_;
}

Result<std::span<const std::byte>> Session::nextStored() {
    while (true) {
        if (entryLeft_ == 0) {
            return std::span<const std::byte>{};
        }
        if (block_ >= folder_.blocks.size()) {
            return fail(
                ErrorKind::Truncated,
                "cabinet data ends before the entry",
                folder_.dataOffset
            );
        }

        const DataBlock& info = folder_.blocks[block_];
        if (!blockLoaded_) {
            if (info.compressedBytes != info.uncompressedBytes) {
                return fail(ErrorKind::Malformed, "cabinet stored block has a size mismatch");
            }
            auto loaded = loadBlock(block_);
            if (!loaded) {
                return std::unexpected(loaded.error());
            }
            blockLoaded_ = true;
            blockPosition_ = 0;
        }

        if (blockPosition_ >= info.uncompressedBytes) {
            ++block_;
            blockLoaded_ = false;
            continue;
        }

        std::uint64_t want = std::min({
            info.uncompressedBytes - blockPosition_,
            entryRoom(),
            static_cast<std::uint64_t>(input_.size()),
        });
        if (want == 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }

        auto chunk = std::span<const std::byte>(payload_).subspan(
            static_cast<std::size_t>(blockPosition_),
            static_cast<std::size_t>(want)
        );
        blockPosition_ += want;

        auto part = deliver(chunk);
        if (!part) {
            return std::unexpected(part.error());
        }
        if (!part->empty()) {
            return *part;
        }
    }
}

Result<std::span<const std::byte>> Session::nextMszip() {
    while (true) {
        if (entryLeft_ == 0) {
            return std::span<const std::byte>{};
        }
        if (block_ >= folder_.blocks.size()) {
            return fail(
                ErrorKind::Truncated,
                "cabinet data ends before the entry",
                folder_.dataOffset
            );
        }

        if (!blockLoaded_) {
            auto loaded = loadBlock(block_);
            if (!loaded) {
                return std::unexpected(loaded.error());
            }
            const DataBlock& info = folder_.blocks[block_];
            if (inflater_ == nullptr) {
                return fail(ErrorKind::LimitExceeded, "MSZIP decoder is missing");
            }
            if (info.uncompressedBytes == 0) {
                if (!payload_.empty()) {
                    return fail(ErrorKind::Malformed, "MSZIP block has trailing data");
                }
                ++block_;
                continue;
            }
            if (payload_.size() < mszipSignature.size() ||
                !std::ranges::equal(mszipSignature, std::span(payload_).first(2))) {
                return fail(ErrorKind::Malformed, "MSZIP block is missing its signature");
            }
            if (streamEnded_) {
                if (auto reset = inflater_->reset(); !reset) {
                    return std::unexpected(reset.error());
                }
                streamEnded_ = false;
                if (!mszipHistory_.empty()) {
                    auto primed = inflater_->setDictionary(mszipHistory_);
                    if (!primed) {
                        return std::unexpected(primed.error());
                    }
                }
            }
            blockLoaded_ = true;
            blockPosition_ = mszipSignature.size();
            blockProduced_ = 0;
        }

        const DataBlock& info = folder_.blocks[block_];
        if (blockProduced_ >= info.uncompressedBytes) {
            ++block_;
            blockLoaded_ = false;
            continue;
        }

        std::uint64_t room = std::min({
            static_cast<std::uint64_t>(output_.size()),
            info.uncompressedBytes - blockProduced_,
            entryRoom(),
        });
        if (room == 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }
        auto window = output_.first(static_cast<std::size_t>(room));

        // NOTE: a deflate tail can resolve entirely from the 32 KiB history
        // after the block's input is exhausted, so drain with empty input
        // before declaring the block truncated.
        std::span<const std::byte> input;
        if (blockPosition_ < payload_.size()) {
            input = std::span<const std::byte>(payload_).subspan(blockPosition_);
        }
        auto step = inflater_->decompress(input, std::span<std::byte>(window));
        if (!step) {
            auto error = step.error();
            error.offset = info.payloadOffset;
            return std::unexpected(error);
        }
        blockPosition_ += step->consumed;
        blockProduced_ += step->produced;
        if (step->finished) {
            streamEnded_ = true;
        }

        if (blockProduced_ > info.uncompressedBytes) {
            return fail(ErrorKind::Malformed, "MSZIP block exceeds its declared size");
        }

        if (step->produced == 0) {
            if (step->consumed == 0) {
                if (blockPosition_ >= payload_.size()) {
                    return fail(
                        ErrorKind::Truncated,
                        "cabinet data ends before the entry",
                        folder_.dataOffset
                    );
                }
                return fail(ErrorKind::Malformed, "MSZIP decoder made no progress");
            }
            continue;
        }

        auto part = deliver(std::span<const std::byte>(window.data(), step->produced));
        if (!part) {
            return std::unexpected(part.error());
        }
        mszipHistory_.insert(
            mszipHistory_.end(),
            window.begin(),
            window.begin() + static_cast<std::ptrdiff_t>(step->produced)
        );
        if (mszipHistory_.size() > 32768) {
            mszipHistory_.erase(
                mszipHistory_.begin(),
                mszipHistory_.begin() + static_cast<std::ptrdiff_t>(mszipHistory_.size() - 32768)
            );
        }
        if (!part->empty()) {
            return *part;
        }
    }
}

Result<std::span<const std::byte>> Session::nextLzx() {
    if (!lzx_) {
        return fail(ErrorKind::LimitExceeded, "LZX decoder is missing");
    }
    LzxDecoder& decoder = *lzx_;
    while (true) {
        if (entryLeft_ == 0) {
            return std::span<const std::byte>{};
        }
        if (!tail_.empty()) {
            auto part = deliver(tail_);
            if (!part) {
                return std::unexpected(part.error());
            }
            tail_ = {};
            if (!part->empty()) {
                return *part;
            }
            continue;
        }

        std::uint64_t emitted = decoder.emitted();
        if (emitted > folder_.uncompressedBytes) {
            return fail(ErrorKind::Malformed, "LZX stream exceeds its cabinet folder");
        }
        if (emitted == folder_.uncompressedBytes) {
            if (lzxDone_) {
                return fail(ErrorKind::Malformed, "cabinet folder data exceeds its entries");
            }
            auto done = decoder.finish();
            if (!done) {
                return std::unexpected(done.error());
            }
            tail_ = *done;
            lzxDone_ = true;
            continue;
        }

        if (lzxStarved_ && inputBlock_ < folder_.blocks.size()) {
            auto loaded = loadBlock(inputBlock_);
            if (!loaded) {
                return std::unexpected(loaded.error());
            }
            auto pushed = decoder.push(payload_);
            if (!pushed) {
                return std::unexpected(pushed.error());
            }
            ++inputBlock_;
            lzxStarved_ = false;
        }

        std::uint64_t room = std::min(static_cast<std::uint64_t>(output_.size()), entryRoom());
        if (room == 0) {
            return fail(ErrorKind::LimitExceeded, "scratch buffer is empty");
        }

        std::uint64_t before = decoder.emitted();
        auto window = output_.first(static_cast<std::size_t>(room));
        auto decoded = decoder.decode(std::span<std::byte>(window));
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        lzxStarved_ = decoded->starved;

        if (decoded->produced == 0) {
            if (decoded->starved) {
                if (inputBlock_ >= folder_.blocks.size()) {
                    return fail(
                        ErrorKind::Truncated,
                        "cabinet data ends before the entry",
                        folder_.dataOffset
                    );
                }
                continue;
            }
            if (decoder.emitted() != before) {
                continue;
            }
            return fail(ErrorKind::Malformed, "LZX decoder made no progress");
        }

        auto part = deliver(std::span<const std::byte>(window.data(), decoded->produced));
        if (!part) {
            return std::unexpected(part.error());
        }
        if (!part->empty()) {
            return *part;
        }
    }
}

}