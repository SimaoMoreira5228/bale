#pragma once

#include "base/error.hpp"
#include "checksum/crc.hpp"
#include "codecs/encoders.hpp"
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

inline constexpr int defaultDeflateLevel = 6;
inline constexpr std::size_t defaultBufferBytes = std::size_t{1} << 20;

enum class WriteKind : std::uint8_t {
    File,
    Directory,
    Symlink,
};

struct WriteEntry {
    std::string_view path{};
    std::string_view linkTarget{};
    std::uint64_t size = 0;
    std::optional<std::int64_t> mtimeSeconds{};
    std::optional<std::uint32_t> mode{};
    WriteKind kind = WriteKind::File;
};

struct WriterOptions {
    int level = defaultDeflateLevel;
    std::size_t bufferBytes = defaultBufferBytes;
};

struct CentralRecord {
    std::string_view name{};
    std::uint64_t localHeaderOffset = 0;
    std::uint64_t compressedSize = 0;
    std::uint64_t uncompressedSize = 0;
    std::optional<std::int32_t> mtimeSeconds{};
    std::uint32_t crc32 = 0;
    std::uint32_t externalAttributes = 0;
    std::uint16_t flags = 0;
    std::uint16_t method = 0;
    std::uint16_t dosTime = 0;
    std::uint16_t dosDate = 0;
};

void appendCentralHeader(const CentralRecord& record, std::vector<std::byte>& out);

void appendEndRecords(
    std::uint64_t entryCount,
    std::uint64_t directoryOffset,
    std::uint64_t directorySize,
    std::vector<std::byte>& out
);

class Writer {
  public:
    [[nodiscard]] static Result<Writer> create(File file, const WriterOptions& options = {});

    [[nodiscard]] std::uint64_t entries() const {
        return entries_;
    }

    [[nodiscard]] Result<void> add(const WriteEntry& entry);

    [[nodiscard]] Result<void> write(std::span<const std::byte> data);

    [[nodiscard]] Result<std::uint64_t> finish(bool durable = false);

  private:
    enum class Phase : std::uint8_t {
        Idle,
        Buffering,
        Streaming,
    };

    Writer(File file, const WriterOptions& options, std::optional<DeflateEncoder> encoder);

    [[nodiscard]] Result<void> check() const;
    [[nodiscard]] Result<void> poison(const Error& error);
    [[nodiscard]] Result<void> put(std::span<const std::byte> data);
    [[nodiscard]] Result<void> flush();
    [[nodiscard]] Result<void> writeLocalHeader(bool reserveZip64);
    [[nodiscard]] Result<void> writeWhole(std::span<const std::byte> data, bool compressible);
    [[nodiscard]] Result<void> startStreaming();
    [[nodiscard]] Result<void> deflate(std::span<const std::byte> data, EncodeFlush flush);
    [[nodiscard]] Result<void> closeEntry();
    [[nodiscard]] Result<void> patchLocalHeader();

    File file_;
    WriterOptions options_;
    std::optional<DeflateEncoder> encoder_;
    std::vector<std::byte> input_;
    std::vector<std::byte> compressed_;
    std::vector<std::byte> output_;
    std::vector<std::byte> header_;
    std::vector<std::byte> central_;
    std::string name_;
    CentralRecord record_;
    Crc32 crc_;
    Phase phase_ = Phase::Idle;
    std::size_t buffered_ = 0;
    std::uint64_t dataLeft_ = 0;
    std::uint64_t position_ = 0;
    std::uint64_t flushed_ = 0;
    std::uint64_t entries_ = 0;
    bool localZip64_ = false;
    std::optional<Error> failure_;
    bool finished_ = false;
};

}
