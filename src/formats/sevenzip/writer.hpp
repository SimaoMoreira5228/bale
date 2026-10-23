#pragma once

#include "base/error.hpp"
#include "formats/sevenzip/encode.hpp"
#include "formats/sevenzip/folder.hpp"
#include "formats/sevenzip/header.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace bale::sevenzip {

inline constexpr int defaultSevenZipLevel = 6;
inline constexpr std::size_t defaultWriterBufferBytes = std::size_t{256} * 1024;

enum class WriteKind : std::uint8_t {
    File,
    Directory,
    Symlink,
};

struct WriteEntry {
    std::string_view path{};
    std::string_view linkTarget{};
    std::uint64_t size = 0;
    std::optional<std::int64_t> mtimeNanoseconds{};
    std::optional<std::uint32_t> mode{};
    WriteKind kind = WriteKind::File;
};

struct WriterOptions {
    Codec codec = Codec::Lzma2;
    int level = defaultSevenZipLevel;
    bool solid = true;
    Limits limits{};
};

class Writer {
  public:
    // NOTE: the writer never emits encrypted, multi-coder or filtered
    // folders: there is no option to request them, so every archive written
    // here stays readable by sevenzip::Reader. Encrypted output is refused
    // by design; unauthenticated CBC has no place in new archives.
    [[nodiscard]] static Result<Writer> create(File file, const WriterOptions& options = {});

    [[nodiscard]] std::uint64_t entries() const {
        return metas_.size();
    }

    [[nodiscard]] Result<void> add(const WriteEntry& entry);

    [[nodiscard]] Result<void> write(std::span<const std::byte> data);

    [[nodiscard]] Result<std::uint64_t> finish(bool durable = false);

  private:
    struct FolderBuild {
        std::vector<std::byte> props;
        std::uint64_t unpackSize = 0;
        std::uint64_t packSize = 0;
        Crc32 packCrc;
        std::vector<std::uint64_t> subSizes;
        std::vector<std::uint32_t> subCrcs;
    };

    struct EntryMeta {
        std::string name;
        std::vector<std::byte> nameUtf16;
        bool hasStream = true;
        bool emptyFile = false;
        bool directory = false;
        std::optional<std::uint64_t> fileTime;
        std::uint32_t attributes = 0;
        std::uint64_t folder = 0;
        std::uint64_t size = 0;
        std::uint32_t crc = 0;
    };

    Writer(File file, const WriterOptions& options) : file_(std::move(file)), options_(options) {
    }

    [[nodiscard]] Result<void> check() const;
    [[nodiscard]] Result<void> poison(const Error& error);
    [[nodiscard]] Result<void> put(std::span<const std::byte> data);
    [[nodiscard]] Result<void> closeEntry();
    [[nodiscard]] Result<void> startStreamFile(const WriteEntry& entry, std::string name);
    [[nodiscard]] Result<void> finishFolder(FolderBuild& folder);
    [[nodiscard]] Result<std::vector<std::byte>> buildHeader() const;

    File file_;
    WriterOptions options_;
    std::vector<FolderBuild> folders_;
    std::vector<EntryMeta> metas_;
    std::unordered_set<std::string> seen_;
    std::optional<FolderEncoder> streamEncoder_;
    std::uint64_t streamFolder_ = 0;
    bool streamOpen_ = false;
    Crc32 entryCrc_;
    std::uint64_t dataLeft_ = 0;
    std::uint64_t position_ = signatureSize;
    std::optional<Error> failure_;
    bool finished_ = false;
};

}
