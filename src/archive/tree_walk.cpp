#include "archive/writer.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <system_error>
#include <unordered_map>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <sys/stat.h>
#endif

namespace bale::archive {

namespace {

namespace fs = std::filesystem;

enum class NodeType : std::uint8_t {
    Regular,
    Directory,
    Symlink,
    Special,
};

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

struct NodeInfo {
    NodeType type = NodeType::Special;
    std::optional<std::int64_t> mtimeNanoseconds;
    std::uint32_t mode = 0;
    FileIdentity identity;
    std::uint64_t links = 1;
};

struct Child {
    std::string name;
    fs::path path;
    bool validName = true;
};

std::unexpected<Error> systemError(std::string_view what, const std::error_code& code) {
    auto failure = fail(ErrorKind::Io, what);
    failure.error().systemCode = code.value();
    return failure;
}

#ifdef _WIN32

[[nodiscard]] bool appendUtf8(std::wstring_view wide, DWORD flags, std::string& out) {
    if (wide.empty()) {
        return true;
    }

    const auto size = static_cast<int>(wide.size());
    const int count =
        WideCharToMultiByte(CP_UTF8, flags, wide.data(), size, nullptr, 0, nullptr, nullptr);
    if (count <= 0) {
        return false;
    }

    out.resize(static_cast<std::size_t>(count));
    WideCharToMultiByte(CP_UTF8, flags, wide.data(), size, out.data(), count, nullptr, nullptr);
    return true;
}

#endif

[[nodiscard]] bool pathBytes(const fs::path& path, std::string& out) {
    out.clear();
#ifdef _WIN32
    const std::wstring wide = path.generic_wstring();
    if (appendUtf8(wide, WC_ERR_INVALID_CHARS, out)) {
        return true;
    }

    out.clear();
    static_cast<void>(appendUtf8(wide, 0, out));
    return false;
#else
    out = path.native();
    return true;
#endif
}

#ifdef _WIN32

Result<NodeInfo> inspect(const fs::path& path) {
    std::error_code error;
    auto status = fs::symlink_status(path, error);
    if (error) {
        return systemError("cannot inspect path", error);
    }

    NodeInfo info;
    info.mode = static_cast<std::uint32_t>(status.permissions()) & maxPermissionBits;
    switch (status.type()) {
    case fs::file_type::regular:
        info.type = NodeType::Regular;
        break;
    case fs::file_type::directory:
        info.type = NodeType::Directory;
        break;
    case fs::file_type::symlink:
        info.type = NodeType::Symlink;
        return info;
    default:
        return info;
    }

    auto written = fs::last_write_time(path, error);
    if (!error) {
        auto system = std::chrono::clock_cast<std::chrono::system_clock>(written);
        auto since =
            std::chrono::duration_cast<std::chrono::nanoseconds>(system.time_since_epoch());
        info.mtimeNanoseconds = since.count();
    }
    return info;
}

#else

std::optional<std::int64_t> combineTime(std::int64_t seconds, std::int64_t nanoseconds) {
    constexpr std::int64_t perSecond = 1'000'000'000;
    constexpr auto max = std::numeric_limits<std::int64_t>::max();
    constexpr auto min = std::numeric_limits<std::int64_t>::min();
    if (seconds > (max - nanoseconds) / perSecond || seconds < min / perSecond) {
        return std::nullopt;
    }
    return seconds * perSecond + nanoseconds;
}

Result<NodeInfo> inspect(const fs::path& path) {
    struct stat status{};
    if (::lstat(path.c_str(), &status) != 0) {
        return systemError("cannot inspect path", std::error_code(errno, std::generic_category()));
    }

    NodeInfo info;
    if (S_ISREG(status.st_mode)) {
        info.type = NodeType::Regular;
    } else if (S_ISDIR(status.st_mode)) {
        info.type = NodeType::Directory;
    } else if (S_ISLNK(status.st_mode)) {
        info.type = NodeType::Symlink;
    }
    info.mode = static_cast<std::uint32_t>(status.st_mode) & maxPermissionBits;
    info.identity.device = static_cast<std::uint64_t>(status.st_dev);
    info.identity.inode = static_cast<std::uint64_t>(status.st_ino);
    info.links = static_cast<std::uint64_t>(status.st_nlink);
#ifdef __APPLE__
    info.mtimeNanoseconds = combineTime(status.st_mtimespec.tv_sec, status.st_mtimespec.tv_nsec);
#else
    info.mtimeNanoseconds = combineTime(status.st_mtim.tv_sec, status.st_mtim.tv_nsec);
#endif
    return info;
}

#endif

}

struct Writer::Walk {
    std::string relative;
    std::uint32_t depth = 0;
    std::optional<FileIdentity> exclude;
    fs::path excludePath;
    std::unordered_map<FileIdentity, NameRef, FileIdentityHash> links;
};

Result<void> Writer::addTree(const fs::path& root, const fs::path& exclude) {
    auto usable = check();
    if (!usable) {
        return usable;
    }

    auto info = inspect(root);
    if (!info) {
        return std::unexpected(info.error());
    }
    if (info->type != NodeType::Directory) {
        return fail(ErrorKind::Unsupported, "tree root is not a directory");
    }

    Walk walk;
    if (!exclude.empty()) {
        auto excluded = inspect(exclude);
        if (excluded && excluded->type == NodeType::Regular) {
            walk.exclude = excluded->identity;
            walk.excludePath = exclude;
        }
    }
    return walkDirectory(walk, root);
}

Result<void> Writer::walkDirectory(Walk& walk, const fs::path& directory) {
    if (walk.depth >= options_.limits.maxDepth) {
        return fail(ErrorKind::LimitExceeded, "directory tree exceeds maximum depth");
    }

    std::vector<Child> children;
    std::error_code error;
    for (fs::directory_iterator it(directory, error), end; !error && it != end;
         it.increment(error)) {
        Child& child = children.emplace_back();
        child.path = it->path();
        child.validName = pathBytes(child.path.filename(), child.name);
    }
    if (error) {
        return systemError("cannot read directory", error);
    }
    std::ranges::sort(children, {}, &Child::name);

    ++walk.depth;
    for (const auto& child : children) {
        std::size_t mark = walk.relative.size();
        if (mark != 0) {
            walk.relative.push_back('/');
        }
        walk.relative.append(child.name);

        auto added = child.validName ? addNode(walk, child.path)
                                     : skipNode(walk, "name is not valid UTF-16");
        walk.relative.resize(mark);
        if (!added) {
            return added;
        }
    }
    --walk.depth;
    return {};
}

Result<void> Writer::skipNode(const Walk& walk, std::string_view reason) {
    skipped_.push_back(
        SkippedPath{
            .path = walk.relative,
            .reason = reason,
        }
    );
    return {};
}

Result<void> Writer::addNode(Walk& walk, const fs::path& node) {
    auto skip = [this, &walk](std::string_view reason) {
        return skipNode(walk, reason);
    };

    auto valid = validateEntryPath(walk.relative, options_.limits, scratch_);
    if (!valid) {
        return skip(valid.error().what);
    }

    auto info = inspect(node);
    if (!info) {
        return std::unexpected(info.error());
    }

    bool excluded = false;
#ifdef _WIN32
    std::error_code error;
    excluded = info->type == NodeType::Regular && !walk.excludePath.empty() &&
        fs::equivalent(node, walk.excludePath, error);
#else
    excluded = walk.exclude && info->identity == *walk.exclude;
#endif
    if (excluded) {
        return skip("the archive being written");
    }

    EntryAttributes attributes{
        .mtimeNanoseconds = info->mtimeNanoseconds,
        .mode = info->mode,
    };
    switch (info->type) {
    case NodeType::Special:
        return skip("special file: device, FIFO or socket");
    case NodeType::Directory: {
        auto added = addDirectory(walk.relative, attributes);
        if (!added) {
            return added;
        }
        return walkDirectory(walk, node);
    }
    case NodeType::Symlink: {
        std::error_code linkError;
        auto target = fs::read_symlink(node, linkError);
        if (linkError) {
            return systemError("cannot read symlink", linkError);
        }
        std::string bytes;
        if (!pathBytes(target, bytes)) {
            return skip("symlink target is not valid UTF-16");
        }
        if (bytes.empty() || bytes.size() > options_.limits.maxPathBytes) {
            return skip("symlink target empty or too long");
        }
        attributes.mode.reset();
        return addSymlink(walk.relative, bytes, attributes);
    }
    case NodeType::Regular:
        break;
    }

    if (info->links > 1) {
        auto found = walk.links.find(info->identity);
        if (found != walk.links.end()) {
            return addHardLink(walk.relative, nameAt(found->second.offset, found->second.size));
        }
    }

    auto file = File::openRegularNoFollow(node);
    if (!file) {
        if (file.error().kind == ErrorKind::Unsupported) {
            return skip("changed type while being archived");
        }
        return std::unexpected(file.error());
    }

    auto added = addFile(walk.relative, *file, attributes);
    if (!added) {
        return added;
    }
    if (info->links > 1) {
        walk.links.emplace(
            info->identity,
            NameRef{
                .offset = entries_.back().pathOffset,
                .size = entries_.back().pathSize,
            }
        );
    }
    return {};
}

}
