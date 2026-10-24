#pragma once

#include "base/error.hpp"
#include "checksum/crc.hpp"
#include "codecs/decoders.hpp"
#include "formats/sevenzip/branch.hpp"
#include "formats/sevenzip/header.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace bale::sevenzip {

enum class Codec : std::uint8_t {
    Copy,
    Lzma1,
    Lzma2,
    Deflate,
    Bzip2,
    Bcj,
};

struct CodecInfo {
    Codec codec = Codec::Copy;
    std::vector<std::byte> props;
    bool encrypted = false;
    bool supported = true;
    bool bcjFilter = false;
    std::string name;
    std::string hex;
};

[[nodiscard]] CodecInfo resolveCodec(const Folder& folder);

struct PackSegment {
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::optional<std::uint32_t> crc;
};

struct FolderPlan {
    CodecInfo codec;
    std::vector<PackSegment> packs;
    std::uint64_t unpackSize = 0;
    std::optional<std::uint32_t> crc;
    std::array<char, 96> failureMessage{};
    std::size_t failureSize = 0;

    [[nodiscard]] bool failed() const {
        return failureSize != 0;
    }

    [[nodiscard]] std::string_view failure() const {
        return {failureMessage.data(), failureSize};
    }
};

[[nodiscard]] Result<FolderPlan> resolveFolder(
    const Folder& folder,
    const std::vector<PackStream>& packs,
    std::uint64_t firstPackStream,
    std::uint64_t packBase,
    std::uint64_t fileSize,
    const Limits& limits
);

class RawLzma {
  public:
    [[nodiscard]] static Result<RawLzma>
    create(Codec codec, std::span<const std::byte> props, std::uint64_t memLimitBytes);

    RawLzma(RawLzma&& other) noexcept;
    RawLzma& operator=(RawLzma&& other) noexcept;
    ~RawLzma();

    [[nodiscard]] Result<DecodeStep>
    decompress(std::span<const std::byte> input, std::span<std::byte> output);

  private:
    struct State;

    explicit RawLzma(std::unique_ptr<State> state);

    std::unique_ptr<State> state_;
};

class FolderSession {
  public:
    [[nodiscard]] static Result<FolderSession> start(
        File file,
        FolderPlan plan,
        const Limits& limits,
        Inflater* inflater,
        Bzip2Decoder* bzip2
    );

    FolderSession(FolderSession&& other) noexcept = default;
    FolderSession& operator=(FolderSession&& other) noexcept = default;
    FolderSession(const FolderSession&) = delete;
    FolderSession& operator=(const FolderSession&) = delete;
    ~FolderSession() = default;

    [[nodiscard]] std::uint64_t position() const {
        return unpackPosition_;
    }

    [[nodiscard]] Result<void> startEntry(
        std::uint64_t offset,
        std::uint64_t size,
        std::optional<std::uint32_t> crc,
        std::span<std::byte> scratch
    );

    [[nodiscard]] Result<std::span<const std::byte>> nextChunk();

  private:
    explicit FolderSession(File file) : file_(std::move(file)) {
    }

    [[nodiscard]] Result<void> prepareDecoder();
    [[nodiscard]] Result<void> fillInput();
    [[nodiscard]] Result<void> noteConsumed(std::size_t count);
    [[nodiscard]] Result<std::span<const std::byte>> deliver(std::span<const std::byte> chunk);
    [[nodiscard]] Result<std::span<const std::byte>> nextCopy();
    [[nodiscard]] Result<std::span<const std::byte>> nextCoded();
    [[nodiscard]] Result<std::span<const std::byte>> nextFiltered();
    [[nodiscard]] Result<std::span<const std::byte>> nextCodedFiltered();
    [[nodiscard]] Result<void> finishEntry();

    File file_;
    FolderPlan plan_;
    std::uint64_t memLimit_ = 0;
    Inflater* inflater_ = nullptr;
    Bzip2Decoder* bzip2_ = nullptr;
    std::variant<std::monostate, Inflater*, Bzip2Decoder*, RawLzma> decoder_;
    BcjFilter bcj_;
    bool useBcj_ = false;
    bool decoderFinished_ = false;
    std::uint64_t packPosition_ = 0;
    std::uint64_t packDataEnd_ = 0;
    std::size_t packSegment_ = 0;
    Crc32 packCrc_;
    std::uint64_t unpackPosition_ = 0;
    Crc32 folderCrc_;
    std::span<std::byte> input_;
    std::span<std::byte> output_;
    std::span<std::byte> filterOutput_;
    std::span<const std::byte> pending_;
    std::uint64_t entryBegin_ = 0;
    std::uint64_t entryEnd_ = 0;
    std::uint64_t entryLeft_ = 0;
    Crc32 entryCrc_;
    std::optional<std::uint32_t> expectedEntryCrc_;
    bool entryActive_ = false;
    bool entryDone_ = true;
};

}
