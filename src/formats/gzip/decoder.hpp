#pragma once

#include "base/error.hpp"
#include "checksum/crc.hpp"
#include "codecs/decoders.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace bale::gzip {

inline constexpr std::size_t fixedHeaderSize = 10;
inline constexpr std::size_t trailerSize = 8;

inline constexpr std::uint8_t flagText = 0x01;
inline constexpr std::uint8_t flagHeaderCrc = 0x02;
inline constexpr std::uint8_t flagExtra = 0x04;
inline constexpr std::uint8_t flagName = 0x08;
inline constexpr std::uint8_t flagComment = 0x10;

struct Limits {
    std::uint64_t maxOutputBytes = std::uint64_t{1} << 40;
    std::size_t maxExtraBytes = 0xFFFF;
    std::size_t maxNameLength = 4096;
    std::size_t maxCommentLength = 4096;
    std::size_t chunkBytes = std::size_t{64} << 10;
};

struct Header {
    std::string_view name;
    std::string_view comment;
    std::span<const std::byte> extra;
    std::size_t size = 0;
    std::uint32_t mtime = 0;
    std::uint8_t flags = 0;
    std::uint8_t extraFlags = 0;
    std::uint8_t os = 0;

    [[nodiscard]] bool text() const {
        return (flags & flagText) != 0;
    }
};

// NOTE: the views point into data. Name and comment are ISO-8859-1 per RFC 1952 and are returned
// undecoded.
[[nodiscard]] Result<Header>
parseHeader(std::span<const std::byte> data, const Limits& limits, std::uint64_t offset = 0);

[[nodiscard]] Result<std::size_t> maxHeaderSize(const Limits& limits);

[[nodiscard]] bool looksLikeGzip(std::span<const std::byte> head);

struct Summary {
    std::uint64_t members = 0;
    std::uint64_t outputBytes = 0;
};

// NOTE: concatenated members decode as one stream. Zero bytes after the last member are accepted
// as padding; any other trailing data is rejected.
class Decoder {
  public:
    [[nodiscard]] static Result<Decoder> open(File file, const Limits& limits = {});

    // NOTE: the first member's header; its views stay valid for the decoder's lifetime.
    [[nodiscard]] const Header& header() const {
        return header_;
    }

    // SECURITY: chunks reach the sink before the member CRC-32 and ISIZE are checked; output is
    // untrusted until the call returns success.
    template <ChunkSink Sink> [[nodiscard]] Result<Summary> decode(Sink&& sink) {
        auto started = startMember(0);
        if (!started) {
            return std::unexpected(started.error());
        }

        summary_ = {};
        summary_.members = 1;
        done_ = false;
        while (true) {
            auto chunk = nextChunk();
            if (!chunk) {
                return std::unexpected(chunk.error());
            }
            if (chunk->empty()) {
                return summary_;
            }

            auto sunk = sink(*chunk);
            if (!sunk) {
                return std::unexpected(sunk.error());
            }
        }
    }

  private:
    Decoder(File file, std::uint64_t fileSize, const Limits& limits, Inflater inflater) :
        file_(std::move(file)), fileSize_(fileSize), limits_(limits),
        inflater_(std::move(inflater)) {
    }

    [[nodiscard]] Result<Header> startMember(std::uint64_t offset);
    [[nodiscard]] Result<std::span<const std::byte>> nextChunk();
    [[nodiscard]] Result<bool> finishMember();
    [[nodiscard]] Result<void> checkPadding(std::uint64_t offset);

    File file_;
    std::uint64_t fileSize_;
    Limits limits_;
    Inflater inflater_;
    std::vector<std::byte> buffer_;
    std::vector<std::byte> firstHeader_;
    Header header_;
    std::span<std::byte> input_;
    std::span<std::byte> output_;
    std::span<const std::byte> pending_;
    std::uint64_t position_ = 0;
    std::uint64_t memberStart_ = 0;
    std::uint64_t memberBytes_ = 0;
    Crc32 crc_;
    Summary summary_;
    bool streamEnded_ = false;
    bool done_ = false;
};

}
