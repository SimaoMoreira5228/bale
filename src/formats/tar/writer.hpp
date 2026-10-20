#pragma once

#include "base/error.hpp"
#include "formats/compressed/output.hpp"
#include "formats/tar/header.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace bale::tar {

inline constexpr std::size_t recordSize = 20 * blockSize;

struct WriteEntry {
    std::string_view path{};
    std::string_view linkTarget{};
    std::string_view uname{};
    std::string_view gname{};
    std::uint64_t size = 0;
    std::uint64_t uid = 0;
    std::uint64_t gid = 0;
    std::int64_t mtimeSeconds = 0;
    std::uint32_t mtimeNanoseconds = 0;
    std::uint32_t mode = 0;
    EntryKind kind = EntryKind::Regular;
};

struct HeaderBuffers {
    std::string path;
    std::string records;
    std::vector<std::byte> blocks;
};

[[nodiscard]] Result<void> encodeHeaders(const WriteEntry& entry, HeaderBuffers& buffers);

class Writer {
  public:
    explicit Writer(CompressedOutput output) : output_(std::move(output)) {
    }

    [[nodiscard]] std::uint64_t entries() const {
        return entries_;
    }

    [[nodiscard]] Result<void> add(const WriteEntry& entry);

    [[nodiscard]] Result<void> write(std::span<const std::byte> data);

    [[nodiscard]] Result<std::uint64_t> finish(bool durable = false);

  private:
    struct StoredLink {
        std::string path;
        std::string linkTarget;
        std::string uname;
        std::string gname;
        std::uint64_t uid = 0;
        std::uint64_t gid = 0;
        std::int64_t mtimeSeconds = 0;
        std::uint32_t mtimeNanoseconds = 0;
        std::uint32_t mode = 0;
    };

    struct ViewHash {
        using is_transparent = void;

        [[nodiscard]] std::size_t operator()(std::string_view text) const noexcept {
            return std::hash<std::string_view>{}(text);
        }
    };

    [[nodiscard]] Result<void> check() const;
    [[nodiscard]] Result<void> closeEntry();
    [[nodiscard]] Result<void> emit(std::span<const std::byte> data);
    [[nodiscard]] Result<void> emitNow(const WriteEntry& entry);
    [[nodiscard]] Result<void> emitLink(const WriteEntry& entry);
    [[nodiscard]] Result<void> commitLast();
    [[nodiscard]] bool targetAvailable(std::string_view target) const;
    [[nodiscard]] Result<void> flushReady();
    [[nodiscard]] Result<void> poison(const Error& error);

    CompressedOutput output_;
    HeaderBuffers buffers_;
    std::vector<StoredLink> pending_;
    std::unordered_set<std::string, ViewHash, std::equal_to<>> available_;
    std::string lastPath_;
    bool lastRegular_ = false;
    std::uint64_t position_ = 0;
    std::uint64_t dataLeft_ = 0;
    std::uint64_t entries_ = 0;
    std::optional<Error> failure_;
    bool finished_ = false;
};

}
