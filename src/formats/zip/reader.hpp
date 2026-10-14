#pragma once

#include "base/error.hpp"
#include "checksum/crc.hpp"
#include "codecs/decoders.hpp"
#include "io/byte_reader.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace bale::zip {

inline constexpr std::size_t endRecordSize = 22;
inline constexpr std::size_t maxEndSearch = endRecordSize + 0xFFFF;

inline constexpr std::uint16_t flagEncrypted = 0x0001;
inline constexpr std::uint16_t flagDataDescriptor = 0x0008;
inline constexpr std::uint16_t flagStrongEncryption = 0x0040;
inline constexpr std::uint16_t flagUtf8 = 0x0800;

inline constexpr std::uint16_t methodStored = 0;
inline constexpr std::uint16_t methodDeflate = 8;

struct Limits {
    std::uint64_t maxEntries = 1'000'000;
    std::uint64_t maxCentralDirectoryBytes = std::uint64_t{256} << 20;
    std::size_t maxNameLength = 4096;
};

struct DosDateTime {
    std::uint16_t year = 1980;
    std::uint8_t month = 1;
    std::uint8_t day = 1;
    std::uint8_t hour = 0;
    std::uint8_t minute = 0;
    std::uint8_t second = 0;
};

[[nodiscard]] DosDateTime decodeDosDateTime(std::uint16_t date, std::uint16_t time);

struct Entry {
    std::string_view name;
    std::span<const std::byte> extra;
    std::string_view comment;
    std::uint64_t compressedSize = 0;
    std::uint64_t uncompressedSize = 0;
    std::uint64_t localHeaderOffset = 0;
    std::optional<std::int64_t> modifiedUnixTime;
    std::optional<std::uint16_t> unixMode;
    std::uint32_t crc32 = 0;
    std::uint32_t externalAttributes = 0;
    std::uint16_t versionMadeBy = 0;
    std::uint16_t versionNeeded = 0;
    std::uint16_t flags = 0;
    std::uint16_t method = 0;
    std::uint16_t dosTime = 0;
    std::uint16_t dosDate = 0;
    std::uint16_t internalAttributes = 0;

    [[nodiscard]] bool encrypted() const {
        return (flags & (flagEncrypted | flagStrongEncryption)) != 0;
    }

    [[nodiscard]] bool hasDataDescriptor() const {
        return (flags & flagDataDescriptor) != 0;
    }

    [[nodiscard]] bool utf8Name() const {
        return (flags & flagUtf8) != 0;
    }
};

[[nodiscard]] Result<std::string_view> nameAsUtf8(const Entry& entry, std::string& storage);

class Cursor {
  public:
    [[nodiscard]] Result<bool> next(Entry& entry);

  private:
    friend class Reader;

    Cursor(
        std::span<const std::byte> directory,
        std::uint64_t fileOffset,
        std::uint64_t directoryOffset,
        std::size_t maxNameLength,
        std::uint64_t entryCount
    ) :
        reader_(directory, fileOffset), directoryOffset_(directoryOffset),
        maxNameLength_(maxNameLength), remaining_(entryCount) {
    }

    ByteReader reader_;
    std::uint64_t directoryOffset_;
    std::size_t maxNameLength_;
    std::uint64_t remaining_;
};

class Reader {
  public:
    [[nodiscard]] static Result<Reader> open(File file, const Limits& limits = {});

    [[nodiscard]] std::uint64_t entryCount() const {
        return entryCount_;
    }

    [[nodiscard]] std::string_view comment() const;

    [[nodiscard]] std::uint64_t prefixSize() const {
        return prefix_;
    }

    [[nodiscard]] bool zip64() const {
        return zip64_;
    }

    [[nodiscard]] Cursor entries() const;

    [[nodiscard]] Result<std::uint64_t> dataOffset(const Entry& entry) const;

    template <ChunkSink Sink>
    [[nodiscard]] Result<void>
    streamEntry(const Entry& entry, std::span<std::byte> scratch, Sink&& sink) {
        auto stream = beginEntry(entry, scratch);
        if (!stream) {
            return std::unexpected(stream.error());
        }

        while (true) {
            auto chunk = nextChunk(*stream);
            if (!chunk) {
                return std::unexpected(chunk.error());
            }
            if (chunk->empty()) {
                return {};
            }

            auto sunk = sink(*chunk);
            if (!sunk) {
                return std::unexpected(sunk.error());
            }
        }
    }

  private:
    explicit Reader(File file) : file_(std::move(file)) {
    }

    struct EntryStream {
        Inflater* inflater = nullptr;
        std::span<std::byte> input;
        std::span<std::byte> output;
        std::span<const std::byte> pending;
        std::uint64_t dataStart = 0;
        std::uint64_t position = 0;
        std::uint64_t inputLeft = 0;
        std::uint64_t outputLeft = 0;
        Crc32 crc;
        std::uint32_t expectedCrc = 0;
        std::uint16_t method = 0;
        bool streamEnded = false;
        bool done = false;
    };

    [[nodiscard]] Result<EntryStream> beginEntry(const Entry& entry, std::span<std::byte> scratch);
    [[nodiscard]] Result<std::span<const std::byte>> nextChunk(EntryStream& stream);
    [[nodiscard]] Result<std::span<const std::byte>> nextStored(EntryStream& stream);
    [[nodiscard]] Result<std::span<const std::byte>> nextDeflated(EntryStream& stream);
    [[nodiscard]] static Result<std::span<const std::byte>> finishEntry(EntryStream& stream);

    File file_;
    std::optional<Inflater> inflater_;
    std::vector<std::byte> buffer_;
    std::size_t directorySize_ = 0;
    std::uint64_t directoryOffset_ = 0;
    std::uint64_t entryCount_ = 0;
    std::uint64_t prefix_ = 0;
    std::size_t maxNameLength_ = 0;
    bool zip64_ = false;
};

[[nodiscard]] bool looksLikeZip(std::span<const std::byte> head, std::span<const std::byte> tail);

}
