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

class Stream {
  public:
    [[nodiscard]] static Result<Stream> open(File file, const Limits& limits = {});

    [[nodiscard]] const Header& header() const {
        return header_;
    }

    [[nodiscard]] std::uint64_t members() const {
        return members_;
    }

    [[nodiscard]] std::uint64_t outputBytes() const {
        return outputBytes_;
    }

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
