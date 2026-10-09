#pragma once

#include "archive/chunk.hpp"
#include "archive/index.hpp"
#include "archive/manifest.hpp"
#include "base/error.hpp"
#include "codecs/zstd_encoder.hpp"
#include "format/record.hpp"
#include "io/file.hpp"
#include "security/budget.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::archive {

class Reader;

struct EntryAttributes {
    std::optional<std::int64_t> mtimeNanoseconds{};
    std::optional<std::uint32_t> mode{};
};

struct WriterOptions {
    std::uint32_t chunkSize = defaultChunkSize;
    CodecId codec = CodecId::Raw;
    std::optional<std::array<std::byte, 16>> archiveId;
    std::optional<std::int64_t> creationTimeNanoseconds;
    std::string_view comment;
    Limits limits;
    bool durable = false;
};

struct SkippedPath {
    std::string path;
    // NOTE: a string literal.
    std::string_view reason;
};

struct WriteSummary {
    std::uint64_t entries = 0;
    std::uint64_t dataRecords = 0;
    std::uint64_t chunkReferences = 0;
    std::uint64_t contentBytes = 0;
    std::uint64_t archiveSize = 0;
};

// NOTE: never seeks or queries the file position, so the output can later be a pipe.
class Writer {
  public:
    [[nodiscard]] static Result<Writer> create(File file, const WriterOptions& options = {});
    [[nodiscard]] static Result<Writer> append(File file, const WriterOptions& options = {});

    [[nodiscard]] Result<void>
    addDirectory(std::string_view path, const EntryAttributes& attributes = {});

    [[nodiscard]] Result<void>
    addFile(std::string_view path, const File& source, const EntryAttributes& attributes = {});

    [[nodiscard]] Result<void> addBytes(
        std::string_view path,
        std::span<const std::byte> data,
        const EntryAttributes& attributes = {}
    );

    [[nodiscard]] Result<void> addSymlink(
        std::string_view path,
        std::string_view target,
        const EntryAttributes& attributes = {}
    );

    [[nodiscard]] Result<void> addHardLink(std::string_view path, std::string_view target);

    [[nodiscard]] Result<void>
    addTree(const std::filesystem::path& root, const std::filesystem::path& exclude = {});

    [[nodiscard]] const std::vector<SkippedPath>& skipped() const {
        return skipped_;
    }

    [[nodiscard]] Result<WriteSummary> finish();

  private:
    struct PendingEntry {
        std::size_t pathOffset = 0;
        std::size_t pathSize = 0;
        std::size_t targetOffset = 0;
        std::size_t targetSize = 0;
        std::uint64_t length = 0;
        std::optional<std::int64_t> mtimeNanoseconds;
        std::optional<std::uint32_t> mode;
        std::uint32_t firstChunk = 0;
        std::uint32_t chunkCount = 0;
        EntryKind kind = EntryKind::Regular;
    };

    struct NameRef {
        std::size_t offset = 0;
        std::size_t size = 0;
    };

    struct RecordSpan {
        std::uint64_t offset = 0;
        std::uint64_t length = 0;
    };

    class ChunkTable {
      public:
        [[nodiscard]] const IndexEntry*
        find(std::span<const IndexEntry> entries, const ChunkKey& key) const;
        void insert(std::span<const IndexEntry> entries, std::uint32_t position);

      private:
        [[nodiscard]] std::size_t slotFor(const ChunkKey& key) const;
        void grow(std::span<const IndexEntry> entries);

        std::vector<std::uint32_t> slots_;
        std::size_t size_ = 0;
    };

    struct Walk;

    Writer(File file, const WriterOptions& options);

    [[nodiscard]] Result<void> check() const;
    [[nodiscard]] Result<void> poison(const Error& error);
    [[nodiscard]] NameRef storeName(std::string_view path);
    [[nodiscard]] Result<PendingEntry*> beginEntry(std::string_view path, EntryKind kind);
    [[nodiscard]] Result<void> appendRaw(std::span<const std::byte> data);
    [[nodiscard]] Result<RecordSpan> writeRecord(
        RecordType type,
        std::span<const std::byte> head,
        std::span<const std::byte> body,
        CodecId codec = CodecId::Raw,
        std::uint64_t decodedLength = 0
    );
    [[nodiscard]] Result<void> storeChunk(std::span<const std::byte> chunk);
    [[nodiscard]] std::string_view nameAt(std::size_t offset, std::size_t size) const;
    [[nodiscard]] Result<void> sortEntries();
    [[nodiscard]] Result<void> resolveHardLinks();
    [[nodiscard]] Result<RecordSpan> writeManifest(Blake3Digest& digest);
    [[nodiscard]] Result<RecordSpan> writeIndex(Blake3Digest& digest);

    [[nodiscard]] Result<void> walkDirectory(Walk& walk, const std::filesystem::path& directory);
    [[nodiscard]] Result<void> addNode(Walk& walk, const std::filesystem::path& node);

    File file_;
    WriterOptions options_;
    std::uint64_t position_ = 0;
    std::uint64_t sequence_ = 0;
    std::uint64_t contentBytes_ = 0;
    std::optional<Error> failure_;
    bool finished_ = false;
    std::uint64_t generation_ = 1;
    Blake3Digest previousCommit_{};
    std::uint64_t previousFooterOffset_ = 0;
    std::vector<std::byte> buffer_;
    std::vector<std::byte> compressionBuffer_;
    std::optional<ZstdEncoder> encoder_;
    std::vector<std::byte> descriptor_;
    std::vector<std::byte> payload_;
    std::string names_;
    std::string scratch_;
    std::vector<PendingEntry> entries_;
    std::vector<ChunkKey> chunks_;
    std::vector<IndexEntry> index_;
    ChunkTable table_;
    std::vector<SkippedPath> skipped_;
};

}
