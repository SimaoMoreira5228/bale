#pragma once

#include "archive/cdc.hpp"
#include "archive/chunk.hpp"
#include "archive/index.hpp"
#include "archive/manifest.hpp"
#include "archive/parity.hpp"
#include "archive/writer_profile.hpp"
#include "base/error.hpp"
#include "crypto/crypto.hpp"
#include "format/record.hpp"
#include "fswalk/tree_walker.hpp"
#include "io/file.hpp"
#include "security/budget.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::archive {

class Reader;
class ChunkPipeline;
struct ChunkSlot;
struct PipelineEvent;

inline constexpr std::uint32_t maxWorkers = 64;

[[nodiscard]] std::uint32_t defaultWorkers();

struct EntryAttributes {
    std::optional<std::int64_t> mtimeNanoseconds{};
    std::optional<std::uint32_t> mode{};
};

struct WriterOptions {
    std::uint32_t chunkSize = defaultChunkSize;
    ChunkPolicy chunkPolicy = ChunkPolicy::Fixed;
    CdcParams cdc = defaultCdcParams;
    CompressionProfile compression = profileFor(Preset::Balanced);
    std::optional<std::array<std::byte, 16>> archiveId;
    std::optional<std::int64_t> creationTimeNanoseconds;
    std::string_view comment;
    Limits limits;
    bool durable = false;
    std::uint32_t workers = defaultWorkers();
    // NOTE: provisional experimental gate; encrypted output is refused unless true.
    bool experimentalEncryption = false;
    ParityConfig parity;
};

struct WriterSecrets {
    bool hasPassword = false;
    crypto::SecretBytes password;
    std::vector<std::array<std::byte, 32>> recipientPublicKeys;
    crypto::KdfParams kdf = crypto::interactiveKdfParams();
};

struct ReaderUnlock {
    bool hasPassword = false;
    crypto::SecretBytes password;
    struct RecipientKey {
        std::array<std::byte, 32> publicKey{};
        crypto::SecretBytes secretKey;
    };
    std::vector<RecipientKey> recipients;
};

struct WriteSummary {
    std::uint64_t entries = 0;
    std::uint64_t dataRecords = 0;
    std::uint64_t chunkReferences = 0;
    std::uint64_t contentBytes = 0;
    std::uint64_t archiveSize = 0;
};

class Writer {
  public:
    [[nodiscard]] static Result<Writer> create(File file, const WriterOptions& options = {});
    [[nodiscard]] static Result<Writer>
    createEncrypted(File file, const WriterOptions& options, WriterSecrets&& secrets);
    [[nodiscard]] static Result<Writer> append(File file, const WriterOptions& options = {});
    [[nodiscard]] static Result<Writer> appendEncrypted(
        File file,
        const WriterOptions& options,
        WriterSecrets&& secrets,
        ReaderUnlock&& unlock
    );
    [[nodiscard]] static Result<WriteSummary>
    compact(File file, Reader& source, bool durable = false);
    [[nodiscard]] static Result<WriteSummary>
    compact(File file, Reader& source, bool durable, std::vector<crypto::SecretBytes> signSeeds);
    [[nodiscard]] static Result<WriteSummary>
    compactEncrypted(File file, Reader& source, bool durable = false);
    [[nodiscard]] static Result<WriteSummary> compactEncrypted(
        File file,
        Reader& source,
        bool durable,
        std::vector<crypto::SecretBytes> signSeeds
    );

    Writer(Writer&& other) noexcept;
    Writer& operator=(Writer&& other) noexcept;
    ~Writer();

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
    beginFile(std::string_view path, const EntryAttributes& attributes = {});

    [[nodiscard]] Result<void> writeFile(std::span<const std::byte> data);

    [[nodiscard]] Result<void> endFile();

    [[nodiscard]] Result<void>
    addTree(const std::filesystem::path& root, const std::filesystem::path& exclude = {});

    [[nodiscard]] const std::vector<SkippedPath>& skipped() const {
        return skipped_;
    }

    [[nodiscard]] Result<WriteSummary> finish();

    [[nodiscard]] Result<void> addSignSeed(crypto::SecretBytes seed);

    [[nodiscard]] std::uint64_t signatureCount() const {
        return signSeeds_.size();
    }

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

    struct OpenFile {
        std::size_t position = 0;
        std::uint64_t length = 0;
        std::size_t filled = 0;
        CdcSplitter cdc;
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

    Writer(File file, const WriterOptions& options);

    [[nodiscard]] static Result<void> checkOptions(const WriterOptions& options);
    [[nodiscard]] static Result<void> checkAttributes(const EntryAttributes& attributes);
    [[nodiscard]] Result<void> startPipeline();
    [[nodiscard]] Result<void> check() const;
    [[nodiscard]] Result<void> poison(const Error& error);
    [[nodiscard]] NameRef storeName(std::string_view path);
    [[nodiscard]] Result<PendingEntry*> beginEntry(std::string_view path, EntryKind kind);
    [[nodiscard]] Result<void> appendRaw(std::span<const std::byte> data);
    [[nodiscard]] Result<void> flushOutput();
    [[nodiscard]] Result<RecordSpan> writeRecord(
        RecordType type,
        std::span<const std::byte> head,
        std::span<const std::byte> body,
        CodecId codec = CodecId::Raw,
        std::uint64_t decodedLength = 0,
        std::uint16_t flags = 0
    );
    [[nodiscard]] Result<RecordSpan> writeKeyslots();
    [[nodiscard]] Result<ChunkSlot*> acquireSlot();
    [[nodiscard]] Result<void> submitChunk(std::size_t size);
    [[nodiscard]] Result<void> pump(bool drain);
    [[nodiscard]] Result<void> handle(const PipelineEvent& event);
    [[nodiscard]] Result<void> appendChunk(ChunkSlot& slot);
    [[nodiscard]] Result<void> appendChunkEncrypted(ChunkSlot& slot);
    [[nodiscard]] Result<void> failInOrder(const Error& error);
    [[nodiscard]] std::string_view nameAt(std::size_t offset, std::size_t size) const;
    [[nodiscard]] Result<void> sortEntries();
    [[nodiscard]] Result<void> resolveHardLinks();
    [[nodiscard]] Result<RecordSpan> writeManifest(Blake3Digest& digest);
    [[nodiscard]] Result<RecordSpan> writeIndex(Blake3Digest& digest);
    [[nodiscard]] Result<ParityDescriptor>
    emitParity(const RecordSpan& manifest, const RecordSpan& index, const RecordSpan& commitRecord);
    [[nodiscard]] Result<void> addWalked(const WalkEntry& entry);
    [[nodiscard]] Result<void>
    addFileCdc(std::string_view path, const File& source, const EntryAttributes& attributes);
    [[nodiscard]] Result<void> writeFileCdc(std::span<const std::byte> data);
    [[nodiscard]] Result<void> writeSignatures(
        const Blake3Digest& commitDigest,
        std::uint64_t generation,
        std::uint64_t epoch
    );

    File file_;
    WriterOptions options_;
    std::uint64_t position_ = 0;
    std::uint64_t sequence_ = 0;
    std::uint64_t contentBytes_ = 0;
    std::uint64_t generationStart_ = superblockSize;
    std::optional<Error> failure_;
    bool finished_ = false;
    std::uint64_t generation_ = 1;
    Blake3Digest previousCommit_{};
    std::uint64_t previousFooterOffset_ = 0;
    std::optional<WriterMetadata> inheritedWriter_;
    std::unique_ptr<ChunkPipeline> pipeline_;
    std::vector<std::byte> output_;
    std::vector<std::byte> descriptor_;
    std::vector<std::byte> payload_;
    std::string names_;
    std::string scratch_;
    std::vector<PendingEntry> entries_;
    std::vector<ChunkKey> chunks_;
    std::vector<std::array<std::byte, 32>> objectIds_;
    std::vector<IndexEntry> index_;
    ChunkTable table_;
    std::vector<SkippedPath> skipped_;
    std::optional<OpenFile> openFile_;
    bool encrypted_ = false;
    std::uint64_t epoch_ = 0;
    crypto::SecretBytes dataKey_;
    std::vector<std::array<std::byte, 32>> recipientPubs_;
    crypto::KdfParams kdf_ = crypto::interactiveKdfParams();
    bool hasPassword_ = false;
    crypto::SecretBytes password_;
    std::array<std::byte, 16> archiveId_{};
    std::vector<crypto::SecretBytes> signSeeds_;
};

}
