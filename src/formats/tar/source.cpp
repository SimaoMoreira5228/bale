#include "formats/tar/source.hpp"

#include <algorithm>
#include <utility>

namespace bale::tar {

namespace {

constexpr std::size_t discardBytes = std::size_t{32} << 10;

}

Result<Source> Source::open(File file) {
    auto size = file.size();
    if (!size) {
        return std::unexpected(size.error());
    }

    return Source(
        Seekable{
            .file = std::move(file),
            .size = *size,
        }
    );
}

Source::Source(CompressedStream stream) : input_(std::move(stream)), discard_(discardBytes) {
}

bool Source::seekable() const {
    return std::holds_alternative<Seekable>(input_);
}

std::optional<std::uint64_t> Source::remaining() const {
    const auto* seekable = std::get_if<Seekable>(&input_);
    if (seekable == nullptr) {
        return std::nullopt;
    }
    return seekable->size - position_;
}

Result<std::size_t> Source::pull(std::span<std::byte> out) {
    auto* seekable = std::get_if<Seekable>(&input_);
    if (seekable == nullptr) {
        auto count = std::get<CompressedStream>(input_).read(out);
        if (count) {
            position_ += *count;
        }
        return count;
    }

    auto count =
        static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), seekable->size - position_));
    auto read = seekable->file.readExactAt(position_, out.first(count));
    if (!read) {
        return std::unexpected(read.error());
    }

    position_ += count;
    return count;
}

Result<std::size_t> Source::readFull(std::span<std::byte> out) {
    std::size_t filled = 0;
    while (filled < out.size()) {
        auto count = pull(out.subspan(filled));
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            break;
        }
        filled += *count;
    }
    return filled;
}

Result<void> Source::skip(std::uint64_t count) {
    if (auto left = remaining()) {
        if (count > *left) {
            return fail(ErrorKind::Truncated, "tar archive ends inside entry data", position_);
        }
        position_ += count;
        return {};
    }

    while (count > 0) {
        auto chunk = std::span(discard_).first(
            static_cast<std::size_t>(std::min<std::uint64_t>(count, discard_.size()))
        );
        auto read = pull(chunk);
        if (!read) {
            return std::unexpected(read.error());
        }
        if (*read == 0) {
            return fail(ErrorKind::Truncated, "tar archive ends inside entry data", position_);
        }
        count -= *read;
    }
    return {};
}

Result<void> Source::finish() {
    if (seekable()) {
        return {};
    }

    while (true) {
        auto read = pull(discard_);
        if (!read) {
            return std::unexpected(read.error());
        }
        if (*read == 0) {
            return {};
        }
    }
}

}
