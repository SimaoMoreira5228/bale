#include "io/file_input.hpp"

#include <algorithm>

namespace bale {

Result<FileInput> FileInput::open(File file, std::size_t capacity) {
    auto size = file.size();
    if (!size) {
        return tl::unexpected<Error>(size.error());
    }

    auto clipped = static_cast<std::size_t>(std::min<std::uint64_t>(capacity, *size));
    return FileInput(std::move(file), *size, clipped);
}

Result<void> FileInput::fill(std::size_t minimum) {
    minimum = std::min(minimum, buffer_.size());
    if (pending_.size() >= minimum || position_ == size_) {
        return {};
    }

    auto kept = pending_.size();
    if (pending_.data() != buffer_.data()) {
        std::ranges::copy(pending_, buffer_.begin());
    }

    auto room =
        static_cast<std::size_t>(std::min<std::uint64_t>(buffer_.size() - kept, size_ - position_));
    auto target = std::span(buffer_).subspan(kept, room);
    auto read = file_.readExactAt(position_, target);
    if (!read) {
        return read;
    }

    position_ += room;
    pending_ = std::span<const std::byte>(buffer_).first(kept + room);
    return {};
}

}
