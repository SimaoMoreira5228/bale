#pragma once

#include "base/error.hpp"
#include "io/file.hpp"
#include "security/budget.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace bale {

inline constexpr std::uint32_t walkPermissionBits = 07777;

enum class WalkKind : std::uint8_t {
    Regular,
    Directory,
    Symlink,
    HardLink,
};

struct WalkEntry {
    std::string_view path{};
    std::string_view target{};
    const File* file = nullptr;
    std::uint64_t size = 0;
    std::optional<std::int64_t> mtimeNanoseconds{};
    std::optional<std::uint32_t> mode{};
    WalkKind kind = WalkKind::Regular;
};

struct WalkOptions {
    Limits limits;
    std::filesystem::path exclude;
    bool hardLinks = true;
};

struct SkippedPath {
    std::string path;
    std::string_view reason;
};

class TreeWalker {
  public:
    [[nodiscard]] static Result<TreeWalker>
    open(const std::filesystem::path& root, const WalkOptions& options = {});

    [[nodiscard]] Result<const WalkEntry*> next();

    [[nodiscard]] const std::vector<SkippedPath>& skipped() const {
        return skipped_;
    }

  private:
    struct FileIdentity {
        std::uint64_t device = 0;
        std::uint64_t inode = 0;

        friend bool operator==(const FileIdentity&, const FileIdentity&) = default;
    };

    struct FileIdentityHash {
        std::size_t operator()(const FileIdentity& identity) const {
            return static_cast<std::size_t>(identity.inode * 0x9E3779B97F4A7C15 ^ identity.device);
        }
    };

    struct Child {
        std::string name;
        std::filesystem::path path;
        bool validName = true;
    };

    struct Frame {
        std::vector<Child> children;
        std::size_t next = 0;
        std::size_t mark = 0;
    };

    explicit TreeWalker(const WalkOptions& options) : options_(options) {
    }

    [[nodiscard]] Result<void> descend(const std::filesystem::path& directory);
    [[nodiscard]] Result<bool> visit(const Child& child);
    [[nodiscard]] Result<bool> skip(std::string_view reason);

    WalkOptions options_;
    std::optional<FileIdentity> exclude_;
    std::vector<Frame> frames_;
    std::size_t depth_ = 0;
    bool pendingDescend_ = false;
    std::string relative_;
    std::string target_;
    std::string scratch_;
    std::optional<File> file_;
    WalkEntry entry_;
    std::unordered_map<FileIdentity, std::string, FileIdentityHash> links_;
    std::vector<SkippedPath> skipped_;
};

}
