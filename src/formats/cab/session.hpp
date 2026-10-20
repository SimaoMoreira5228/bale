#pragma once

#include "base/error.hpp"
#include "codecs/decoders.hpp"
#include "formats/cab/header.hpp"
#include "formats/cab/lzx.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace bale::cab {

class Session {
  public:
    [[nodiscard]] static Result<Session> start(File file, const Folder& folder, Inflater* inflater);
    [[nodiscard]] std::uint64_t position() const;
    [[nodiscard]] Result<void>
    startEntry(std::uint64_t offset, std::uint64_t size, std::span<std::byte> scratch);
    [[nodiscard]] Result<std::span<const std::byte>> nextChunk();

    Session(Session&& other) noexcept = default;
    Session& operator=(Session&& other) noexcept = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    ~Session() = default;

  private:
    Session(File file, const Folder& folder, Inflater* inflater);
    [[nodiscard]] Result<void> loadBlock(std::size_t block);
    [[nodiscard]] Result<std::span<const std::byte>> deliver(std::span<const std::byte> chunk);
    [[nodiscard]] std::uint64_t entryRoom() const;
    [[nodiscard]] Result<std::span<const std::byte>> nextStored();
    [[nodiscard]] Result<std::span<const std::byte>> nextMszip();
    [[nodiscard]] Result<std::span<const std::byte>> nextLzx();

    File file_;
    Folder folder_;
    Inflater* inflater_ = nullptr;
    std::optional<LzxDecoder> lzx_;

    std::uint64_t folderPosition_ = 0;
    std::uint64_t entryBegin_ = 0;
    std::uint64_t entryEnd_ = 0;
    std::uint64_t entryLeft_ = 0;

    std::span<std::byte> input_;
    std::span<std::byte> output_;

    std::vector<std::byte> payload_;
    std::span<const std::byte> tail_;
    std::vector<std::byte> mszipHistory_;
    std::size_t block_ = 0;
    bool blockLoaded_ = false;
    std::uint64_t blockPosition_ = 0;
    std::uint64_t blockProduced_ = 0;
    bool streamEnded_ = false;

    std::size_t inputBlock_ = 0;
    bool lzxStarved_ = true;
    bool lzxDone_ = false;
};

}
