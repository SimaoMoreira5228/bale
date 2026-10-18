#pragma once

#include "archive/chunk.hpp"
#include "archive/chunk_codec.hpp"
#include "archive/commit.hpp"
#include "archive/index.hpp"
#include "archive/manifest.hpp"
#include "base/error.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"
#include "io/chunk_sink.hpp"
#include "io/file.hpp"
#include "security/budget.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace bale::archive {

struct ReaderOptions {
    Limits limits;
    std::uint64_t footerScanBlockSize = std::uint64_t{1} << 20;
    std::uint64_t maxMetadataBytes = std::uint64_t{256} << 20;
    std::uint64_t maxGenerations = 100'000;
};

enum class VerifyMode : std::uint8_t {
    Structure,
    Content,
};

struct VerifyReport {
    std::uint64_t records = 0;
    std::uint64_t dataRecords = 0;
    std::uint64_t unindexedDataRecords = 0;
    std::uint64_t chunksVerified = 0;
    std::uint64_t bytesVerified = 0;
};

class Reader {
  public:
    [[nodiscard]] static Result<Reader> open(File file, const ReaderOptions& options = {});

    [[nodiscard]] const Superblock& superblock() const {
        return superblock_;
    }

    [[nodiscard]] const Commit& commit() const {
        return commit_;
    }

    [[nodiscard]] const Blake3Digest& commitDigest() const {
        return commitDigest_;
    }

    [[nodiscard]] const Manifest& manifest() const {
        return manifest_;
    }

    [[nodiscard]] std::span<const IndexEntry> index() const {
        return index_;
    }

    [[nodiscard]] std::uint64_t footerOffset() const {
        return footerOffset_;
    }

    [[nodiscard]] std::uint64_t ignoredTrailingBytes() const {
        return fileSize_ - footerOffset_ - footerSize;
    }

    // NOTE: the returned span lives in a buffer reused by the next call.
    [[nodiscard]] Result<std::span<const std::byte>> loadChunk(const ChunkKey& key);

    template <ChunkSink Sink>
    [[nodiscard]] Result<void> streamFile(const ManifestEntry& entry, Sink&& sink) {
        if (entry.kind != EntryKind::Regular) {
            return fail(ErrorKind::Malformed, "entry is not a regular file");
        }

        for (const auto& key : manifest_.chunksOf(entry)) {
            auto chunk = loadChunk(key);
            if (!chunk) {
                return std::unexpected(chunk.error());
            }
            auto sunk = sink(*chunk);
            if (!sunk) {
                return sunk;
            }
        }
        return {};
    }

    [[nodiscard]] Result<VerifyReport> verify(VerifyMode mode);

  private:
    friend class Writer;

    struct Generation {
        Footer footer;
        Commit commit;
        Blake3Digest digest{};
        std::uint64_t footerOffset = 0;
    };

    Reader(File file, const ReaderOptions& options, std::uint64_t fileSize) :
        file_(std::move(file)), options_(options), fileSize_(fileSize) {
    }

    [[nodiscard]] Result<void> findCommit();
    [[nodiscard]] Result<void> tryFooter(std::span<const std::byte> bytes, std::uint64_t offset);
    [[nodiscard]] Result<Record> readRecord(
        std::uint64_t offset,
        std::uint64_t length,
        RecordType type,
        std::uint64_t maxPayload,
        std::vector<std::byte>& buffer
    );
    [[nodiscard]] Result<void> loadMetadata();
    [[nodiscard]] Result<void> checkLocations();
    [[nodiscard]] Result<VerifyReport> walkRecords();

    File file_;
    ReaderOptions options_;
    std::uint64_t fileSize_ = 0;
    std::uint64_t footerOffset_ = 0;
    Superblock superblock_;
    Footer footer_;
    Commit commit_;
    Blake3Digest commitDigest_{};
    std::vector<std::byte> manifestBytes_;
    std::vector<std::byte> indexBytes_;
    std::vector<std::byte> buffer_;
    std::vector<std::byte> decodedBuffer_;
    std::vector<std::byte> descriptor_;
    ChunkDecoder chunkDecoder_;
    Manifest manifest_;
    std::vector<IndexEntry> index_;
    std::vector<std::uint32_t> byOffset_;
    std::vector<Generation> generations_;
};

}
