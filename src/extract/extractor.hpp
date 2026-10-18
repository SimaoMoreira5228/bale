#pragma once

#include "base/error.hpp"
#include "security/archive_path.hpp"
#include "security/budget.hpp"
#include "security/case_fold.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale {

enum class OverwritePolicy : std::uint8_t {
    Never,
    Replace,
    Skip,
};

enum class SymlinkPolicy : std::uint8_t {
    Refuse,
    Skip,
    AllowContained,
};

enum class HardLinkPolicy : std::uint8_t {
    Allow,
    Refuse,
};

enum class SpecialFilePolicy : std::uint8_t {
    Skip,
    Refuse,
};

enum class SpecialFileKind : std::uint8_t {
    CharacterDevice,
    BlockDevice,
    Fifo,
    Socket,
};

#if defined(_WIN32) || defined(__APPLE__)
inline constexpr bool hostCaseInsensitive = true;
#else
inline constexpr bool hostCaseInsensitive = false;
#endif

struct ExtractPolicy {
    Limits limits;
    OverwritePolicy overwrite = OverwritePolicy::Never;
    SymlinkPolicy symlinks = SymlinkPolicy::Refuse;
    HardLinkPolicy hardLinks = HardLinkPolicy::Allow;
    SpecialFilePolicy specialFiles = SpecialFilePolicy::Skip;
    bool caseInsensitive = hostCaseInsensitive;
    bool durable = false;
    bool restoreMtime = true;
    bool restoreSpecialModeBits = false;
    std::uint32_t umask = 0022;
};

struct EntryMetadata {
    std::optional<std::uint32_t> mode;
    std::optional<std::int64_t> mtimeNanoseconds;
};

enum class EntryOutcome : std::uint8_t {
    Extracted,
    Skipped,
};

struct EntryResult {
    EntryOutcome outcome = EntryOutcome::Extracted;
    std::string_view reason;
};

class OsHandle {
  public:
#ifdef _WIN32
    using Native = void*;
    static inline Native const invalid = reinterpret_cast<Native>(~std::uintptr_t{0});
#else
    using Native = int;
    static constexpr Native invalid = -1;
#endif

    OsHandle() = default;

    explicit OsHandle(Native native) : native_(native) {
    }

    OsHandle(const OsHandle&) = delete;
    OsHandle& operator=(const OsHandle&) = delete;
    OsHandle(OsHandle&& other) noexcept;
    OsHandle& operator=(OsHandle&& other) noexcept;
    ~OsHandle();

    [[nodiscard]] Native get() const {
        return native_;
    }

    [[nodiscard]] bool valid() const {
        return native_ != invalid;
    }

    void reset();

  private:
    Native native_ = invalid;
};

inline constexpr std::size_t maxLeafBytes = 255;

class Extractor;

class PendingFile {
  public:
    PendingFile(const PendingFile&) = delete;
    PendingFile& operator=(const PendingFile&) = delete;
    PendingFile(PendingFile&& other) noexcept;
    PendingFile& operator=(PendingFile&& other) noexcept;
    ~PendingFile();

    [[nodiscard]] bool skipping() const {
        return state_ == State::Skipping;
    }

    [[nodiscard]] Result<void> write(std::span<const std::byte> data);
    [[nodiscard]] Result<EntryResult> commit();

  private:
    friend class Extractor;

    enum class State : std::uint8_t {
        Writing,
        Skipping,
        Failed,
        Done,
    };

    explicit PendingFile(Extractor& owner) : owner_(&owner) {
    }

    [[nodiscard]] std::string_view leaf() const {
        return {leaf_.data(), leafSize_};
    }

    void discard();

    Extractor* owner_;
    OsHandle directory_;
    OsHandle file_;
    EntryMetadata metadata_;
    std::array<char, 32> tempName_{};
    std::array<char, maxLeafBytes + 1> leaf_{};
    std::size_t leafSize_ = 0;
    State state_ = State::Writing;
};

class Extractor {
  public:
    struct FileId {
        std::uint64_t device = 0;
        std::uint64_t inode = 0;

        friend bool operator==(const FileId&, const FileId&) = default;
    };

    [[nodiscard]] static Result<Extractor>
    open(const std::filesystem::path& destinationRoot, const ExtractPolicy& policy = {});

    Extractor(const Extractor&) = delete;
    Extractor& operator=(const Extractor&) = delete;
    Extractor(Extractor&&) noexcept = default;
    Extractor& operator=(Extractor&&) noexcept = default;
    ~Extractor() = default;

    [[nodiscard]] Result<EntryResult>
    createDirectory(const ArchivePath& path, const EntryMetadata& metadata = {});

    [[nodiscard]] Result<PendingFile>
    beginFile(const ArchivePath& path, const EntryMetadata& metadata = {});

    [[nodiscard]] Result<EntryResult> createSymlink(
        const ArchivePath& path,
        std::string_view target,
        const EntryMetadata& metadata = {}
    );

    [[nodiscard]] Result<EntryResult>
    createHardLink(const ArchivePath& path, const ArchivePath& existingPath);

    [[nodiscard]] Result<EntryResult>
    skipOrRefuseSpecialFile(const ArchivePath& path, SpecialFileKind kind);

    [[nodiscard]] Result<void> finish();

    [[nodiscard]] const Budget& budget() const {
        return budget_;
    }

  private:
    friend class PendingFile;

    class FileIdSet {
      public:
        void insert(FileId id);
        [[nodiscard]] bool contains(FileId id) const;

      private:
        [[nodiscard]] std::size_t slotFor(FileId id) const;
        void grow();

        std::vector<FileId> slots_;
        std::size_t size_ = 0;
    };

    struct EntryPath {
        std::string_view leaf;
        std::uint32_t parentDepth = 0;
    };

    struct DeferredTime {
        FileId id;
        std::int64_t mtimeNanoseconds = 0;
        std::size_t pathOffset = 0;
        std::uint32_t pathSize = 0;
        std::uint32_t depth = 0;
    };

    using TempName = std::array<char, 32>;

    Extractor(OsHandle root, const ExtractPolicy& policy);

    [[nodiscard]] static Result<EntryPath> splitPath(std::string_view path);
    [[nodiscard]] Result<EntryPath> beginEntry(const ArchivePath& path);
    [[nodiscard]] Result<std::string_view>
    normalizeLinkTarget(std::string_view target, std::uint32_t parentDepth);
    [[nodiscard]] std::uint32_t fileMode(const EntryMetadata& metadata) const;
    [[nodiscard]] std::uint32_t directoryMode(const EntryMetadata& metadata) const;
    void nextTempName(TempName& name);
    void deferDirectoryTime(const ArchivePath& path, FileId id, std::int64_t mtimeNanoseconds);
    [[nodiscard]] Result<void> applyDeferredTime(std::string_view path, const DeferredTime& time);

    [[nodiscard]] Result<OsHandle> openParent(std::string_view path, bool create);
    [[nodiscard]] Result<OsHandle> openTemporary(const OsHandle& directory, TempName& name);
    [[nodiscard]] Result<void> writeData(const OsHandle& file, std::span<const std::byte> data);
    [[nodiscard]] Result<EntryResult> place(
        const OsHandle& directory,
        const OsHandle& entry,
        const char* tempName,
        std::string_view leaf
    );
    [[nodiscard]] Result<EntryResult> finishFile(PendingFile& file);
    void removeTemporary(const OsHandle& directory, const OsHandle& file, const char* tempName);

    OsHandle root_;
    ExtractPolicy policy_;
    Budget budget_;
    CaseFoldSet caseFold_;
    FileIdSet extractedFiles_;
    std::vector<DeferredTime> deferredTimes_;
    std::string deferredPaths_;
    std::string component_;
    std::string linkTarget_;
    std::uint64_t tempSeed_ = 0;
    std::uint64_t tempCounter_ = 0;
};

}
