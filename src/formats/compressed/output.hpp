#pragma once

#include "base/error.hpp"
#include "checksum/crc.hpp"
#include "codecs/encoders.hpp"
#include "formats/compressed/stream.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <variant>
#include <vector>

namespace bale {

inline constexpr int defaultGzipLevel = 6;
inline constexpr int defaultZstdOutputLevel = 3;

class CompressedOutput {
  public:
    [[nodiscard]] static Result<CompressedOutput>
    create(File file, Compression compression, std::optional<int> level = std::nullopt);

    [[nodiscard]] std::uint64_t inputBytes() const {
        return inputBytes_;
    }

    [[nodiscard]] Result<void> write(std::span<const std::byte> data);

    [[nodiscard]] Result<std::uint64_t> finish(bool durable = false);

  private:
    using Encoder = std::variant<std::monostate, DeflateEncoder, ZstdEncoder>;

    CompressedOutput(File file, Encoder encoder, std::size_t bufferSize) :
        file_(std::move(file)), encoder_(std::move(encoder)), buffer_(bufferSize) {
    }

    [[nodiscard]] Result<void> encode(std::span<const std::byte> data, EncodeFlush flush);
    [[nodiscard]] Result<void> put(std::span<const std::byte> data);
    [[nodiscard]] Result<void> flush();
    [[nodiscard]] Result<void> poison(const Error& error);

    File file_;
    Encoder encoder_;
    std::vector<std::byte> buffer_;
    std::size_t used_ = 0;
    Crc32 crc_;
    std::uint64_t inputBytes_ = 0;
    std::uint64_t outputBytes_ = 0;
    std::optional<Error> failure_;
    bool finished_ = false;
};

}
