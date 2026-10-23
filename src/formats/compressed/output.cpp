#include "formats/compressed/output.hpp"

#include "base/checked.hpp"
#include "formats/gzip/header.hpp"

#include <algorithm>
#include <type_traits>
#include <variant>

namespace bale {

namespace {

constexpr std::size_t outputBufferSize = std::size_t{256} * 1024;

}

Result<CompressedOutput>
CompressedOutput::create(File file, Compression compression, std::optional<int> level) {
    switch (compression) {
    case Compression::None:
        if (level) {
            return fail(ErrorKind::Unsupported, "uncompressed output takes no level");
        }
        return CompressedOutput(std::move(file), Encoder(), outputBufferSize);
    case Compression::Gzip: {
        int chosen = level.value_or(defaultGzipLevel);
        auto encoder = DeflateEncoder::create(chosen);
        if (!encoder) {
            return tl::unexpected<Error>(encoder.error());
        }

        CompressedOutput output(std::move(file), Encoder(std::move(*encoder)), outputBufferSize);
        auto header = gzip::encodeHeader(chosen);
        auto written = output.put(header);
        if (!written) {
            return tl::unexpected<Error>(written.error());
        }
        return output;
    }
    case Compression::Zstd: {
        auto encoder = ZstdEncoder::create(level.value_or(defaultZstdOutputLevel), true);
        if (!encoder) {
            return tl::unexpected<Error>(encoder.error());
        }
        return CompressedOutput(std::move(file), Encoder(std::move(*encoder)), outputBufferSize);
    }
    case Compression::Xz:
    case Compression::Bzip2:
        return fail(ErrorKind::Unsupported, "xz and bzip2 output is not supported");
    }
    return fail(ErrorKind::Unsupported, "unknown output compression");
}

Result<void> CompressedOutput::poison(const Error& error) {
    failure_ = error;
    return tl::unexpected<Error>(error);
}

Result<void> CompressedOutput::flush() {
    if (used_ == 0) {
        return {};
    }

    auto written = file_.append(std::span(buffer_).first(used_));
    if (!written) {
        return poison(written.error());
    }
    outputBytes_ += used_;
    used_ = 0;
    return {};
}

Result<void> CompressedOutput::put(std::span<const std::byte> data) {
    if (used_ + data.size() > buffer_.size()) {
        auto flushed = flush();
        if (!flushed) {
            return flushed;
        }
    }

    if (data.size() >= buffer_.size()) {
        auto written = file_.append(data);
        if (!written) {
            return poison(written.error());
        }
        outputBytes_ += data.size();
        return {};
    }

    std::ranges::copy(data, buffer_.begin() + static_cast<std::ptrdiff_t>(used_));
    used_ += data.size();
    return {};
}

Result<void> CompressedOutput::encode(std::span<const std::byte> data, EncodeFlush flush) {
    while (true) {
        if (used_ == buffer_.size()) {
            auto flushed = this->flush();
            if (!flushed) {
                return flushed;
            }
        }

        auto room = std::span(buffer_).subspan(used_);
        auto step = std::visit(
            [&](auto& encoder) -> Result<EncodeStep> {
                if constexpr (std::is_same_v<std::decay_t<decltype(encoder)>, std::monostate>) {
                    return fail(ErrorKind::Unsupported, "output has no encoder");
                } else {
                    return encoder.stream(data, room, flush);
                }
            },
            encoder_
        );
        if (!step) {
            return poison(step.error());
        }

        data = data.subspan(step->consumed);
        used_ += step->produced;
        if (step->finished) {
            return {};
        }
    }
}

Result<void> CompressedOutput::write(std::span<const std::byte> data) {
    if (failure_) {
        return tl::unexpected<Error>(*failure_);
    }
    if (finished_) {
        return fail(ErrorKind::Malformed, "output already finished");
    }

    auto total = checkedAdd(inputBytes_, data.size());
    if (!total) {
        return poison(Error{.kind = ErrorKind::LimitExceeded, .what = "output size overflows"});
    }
    inputBytes_ = *total;

    if (std::holds_alternative<std::monostate>(encoder_)) {
        return put(data);
    }
    if (std::holds_alternative<DeflateEncoder>(encoder_)) {
        crc_.update(data);
    }
    if (data.empty()) {
        return {};
    }
    return encode(data, EncodeFlush::None);
}

Result<std::uint64_t> CompressedOutput::finish(bool durable) {
    if (failure_) {
        return tl::unexpected<Error>(*failure_);
    }
    if (finished_) {
        return fail(ErrorKind::Malformed, "output already finished");
    }

    if (!std::holds_alternative<std::monostate>(encoder_)) {
        auto ended = encode({}, EncodeFlush::Finish);
        if (!ended) {
            return tl::unexpected<Error>(ended.error());
        }
    }
    if (std::holds_alternative<DeflateEncoder>(encoder_)) {
        auto trailer = gzip::encodeTrailer(crc_.value(), inputBytes_);
        auto written = put(trailer);
        if (!written) {
            return tl::unexpected<Error>(written.error());
        }
    }

    auto flushed = flush();
    if (!flushed) {
        return tl::unexpected<Error>(flushed.error());
    }
    if (durable) {
        auto synced = file_.sync();
        if (!synced) {
            return tl::unexpected<Error>(poison(synced.error()).error());
        }
    }

    finished_ = true;
    return outputBytes_;
}

}
