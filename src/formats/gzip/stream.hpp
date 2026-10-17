#pragma once

#include "base/error.hpp"
#include "checksum/crc.hpp"
#include "codecs/decoders.hpp"
#include "formats/gzip/header.hpp"
#include "io/file.hpp"
#include "io/file_input.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace bale::gzip {

// NOTE: concatenated members decode as one stream. Zero bytes after the last member are accepted
// as padding; any other trailing data is rejected. After an error every later read returns it.
class Stream {
  public:
    [[nodiscard]] static Result<Stream> open(File file, const Limits& limits = {});

    // NOTE: the first member's header; its views stay valid for the stream's lifetime.
    [[nodiscard]] const Header& header() const {
        return header_;
    }

    [[nodiscard]] std::uint64_t members() const {
        return members_;
    }

    [[nodiscard]] std::uint64_t outputBytes() const {
        return outputBytes_;
    }

    // NOTE: 0 means the last member ended and every trailer and the padding after it were verified.
    // SECURITY: bytes are returned before their member's CRC-32 and ISIZE are checked; output is
    // untrusted until a read returns 0.
    [[nodiscard]] Result<std::size_t> read(std::span<std::byte> out);

  private:
    Stream(FileInput input, const Limits& limits, std::size_t headerLimit, Inflater inflater) :
        input_(std::move(input)), limits_(limits), headerLimit_(headerLimit),
        inflater_(std::move(inflater)) {
    }

    [[nodiscard]] Result<std::size_t> decode(std::span<std::byte> out);
    [[nodiscard]] Result<Header> beginMember();
    [[nodiscard]] Result<bool> finishMember();
    [[nodiscard]] Result<void> checkPadding();

    FileInput input_;
    Limits limits_;
    std::size_t headerLimit_;
    Inflater inflater_;
    std::vector<std::byte> firstHeader_;
    Header header_;
    std::uint64_t memberStart_ = 0;
    std::uint64_t memberBytes_ = 0;
    std::uint64_t members_ = 1;
    std::uint64_t outputBytes_ = 0;
    Crc32 crc_;
    std::optional<Error> failure_;
    bool memberEnded_ = false;
    bool done_ = false;
};

}
