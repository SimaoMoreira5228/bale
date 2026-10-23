#include "fswalk/tree_walker.hpp"

#include "security/archive_path.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <system_error>
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

namespace bale {

namespace {

namespace fs = std::filesystem;

constexpr PathPolicy walkPathPolicy{
    .backslash = Backslash::Reject,
    .syntax = PathSyntax::Strict,
    .windowsSafe = false,
    .allowRawNames = false,
};

enum class NodeType : std::uint8_t {
    Regular,
    Directory,
    Symlink,
    Special,
};

struct NodeInfo {
    NodeType type = NodeType::Special;
    std::optional<std::int64_t> mtimeNanoseconds;
    std::uint32_t mode = 0;
    std::uint64_t device = 0;
    std::uint64_t inode = 0;
    std::uint64_t links = 1;
};

tl::unexpected<Error> systemError(std::string_view what, const std::error_code& code) {
    auto failure = fail(ErrorKind::Io, what);
    failure.value().systemCode = code.value();
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
    info.mode = static_cast<std::uint32_t>(status.permissions()) & walkPermissionBits;
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
    info.mode = static_cast<std::uint32_t>(status.st_mode) & walkPermissionBits;
    info.device = static_cast<std::uint64_t>(status.st_dev);
    info.inode = static_cast<std::uint64_t>(status.st_ino);
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

Result<TreeWalker> TreeWalker::open(const fs::path& root, const WalkOptions& options) {
    auto info = inspect(root);
    if (!info) {
        return tl::unexpected<Error>(info.error());
    }
    if (info->type != NodeType::Directory) {
        return fail(ErrorKind::Unsupported, "tree root is not a directory");
    }

    TreeWalker walker(options);
    if (!options.exclude.empty()) {
        auto excluded = inspect(options.exclude);
        if (excluded && excluded->type == NodeType::Regular) {
            walker.exclude_ = FileIdentity{.device = excluded->device, .inode = excluded->inode};
        } else {
            walker.options_.exclude.clear();
        }
    }

    auto listed = walker.descend(root);
    if (!listed) {
        return tl::unexpected<Error>(listed.error());
    }
    return walker;
}

Result<void> TreeWalker::descend(const fs::path& directory) {
    if (depth_ >= options_.limits.maxDepth) {
        return fail(ErrorKind::LimitExceeded, "directory tree exceeds maximum depth");
    }
    if (frames_.size() == depth_) {
        frames_.emplace_back();
    }

    Frame& frame = frames_[depth_];
    frame.children.clear();
    frame.next = 0;
    frame.mark = relative_.size();

    std::error_code error;
    for (fs::directory_iterator it(directory, error), end; !error && it != end;
         it.increment(error)) {
        Child& child = frame.children.emplace_back();
        child.path = it->path();
        child.validName = pathBytes(child.path.filename(), child.name);
    }
    if (error) {
        return systemError("cannot read directory", error);
    }
    std::ranges::sort(frame.children, {}, &Child::name);

    ++depth_;
    return {};
}

Result<const WalkEntry*> TreeWalker::next() {
    file_.reset();
    if (pendingDescend_) {
        pendingDescend_ = false;
        const Frame& parent = frames_[depth_ - 1];
        fs::path directory = parent.children[parent.next - 1].path;
        auto listed = descend(directory);
        if (!listed) {
            return tl::unexpected<Error>(listed.error());
        }
    }

    while (depth_ > 0) {
        Frame& frame = frames_[depth_ - 1];
        if (frame.next == frame.children.size()) {
            relative_.resize(frame.mark);
            --depth_;
            continue;
        }

        const Child& child = frame.children[frame.next];
        ++frame.next;
        relative_.resize(frame.mark);
        if (!relative_.empty()) {
            relative_.push_back('/');
        }
        relative_.append(child.name);

        auto produced = visit(child);
        if (!produced) {
            return tl::unexpected<Error>(produced.error());
        }
        if (*produced) {
            return &entry_;
        }
    }
    return nullptr;
}

Result<bool> TreeWalker::skip(std::string_view reason) {
    skipped_.push_back(
        SkippedPath{
            .path = relative_,
            .reason = reason,
        }
    );
    return false;
}

Result<bool> TreeWalker::visit(const Child& child) {
    if (!child.validName) {
        return skip("name is not valid UTF-16");
    }

    auto normalized = normalizeArchivePath(
        std::as_bytes(std::span(relative_)),
        walkPathPolicy,
        options_.limits,
        scratch_
    );
    if (!normalized) {
        return skip(normalized.error().what);
    }
    if (normalized->path != relative_) {
        return skip("path is not canonical");
    }

    auto info = inspect(child.path);
    if (!info) {
        return tl::unexpected<Error>(info.error());
    }

    bool excluded = false;
#ifdef _WIN32
    std::error_code error;
    excluded = info->type == NodeType::Regular && !options_.exclude.empty() &&
        fs::equivalent(child.path, options_.exclude, error);
#else
    excluded = exclude_ && info->device == exclude_->device && info->inode == exclude_->inode;
#endif
    if (excluded) {
        return skip("the archive being written");
    }

    entry_ = WalkEntry{
        .path = relative_,
        .mtimeNanoseconds = info->mtimeNanoseconds,
        .mode = info->mode,
    };
    switch (info->type) {
    case NodeType::Special:
        return skip("special file: device, FIFO or socket");
    case NodeType::Directory:
        entry_.kind = WalkKind::Directory;
        pendingDescend_ = true;
        return true;
    case NodeType::Symlink: {
        std::error_code linkError;
        auto target = fs::read_symlink(child.path, linkError);
        if (linkError) {
            return systemError("cannot read symlink", linkError);
        }
        if (!pathBytes(target, target_)) {
            return skip("symlink target is not valid UTF-16");
        }
        if (target_.empty() || target_.size() > options_.limits.maxPathBytes ||
            target_.find('\0') != std::string::npos) {
            return skip("symlink target empty or too long");
        }
        entry_.kind = WalkKind::Symlink;
        entry_.target = target_;
        entry_.mode.reset();
        return true;
    }
    case NodeType::Regular:
        break;
    }

    FileIdentity identity{.device = info->device, .inode = info->inode};
    bool shared = options_.hardLinks && info->links > 1;
    if (shared) {
        auto found = links_.find(identity);
        if (found != links_.end()) {
            entry_.kind = WalkKind::HardLink;
            entry_.target = found->second;
            return true;
        }
    }

    auto file = File::openRegularNoFollow(child.path);
    if (!file) {
        if (file.error().kind == ErrorKind::Unsupported) {
            return skip("changed type while being archived");
        }
        return tl::unexpected<Error>(file.error());
    }
    auto size = file->size();
    if (!size) {
        return tl::unexpected<Error>(size.error());
    }

    file_.emplace(std::move(*file));
    entry_.kind = WalkKind::Regular;
    entry_.file = &*file_;
    entry_.size = *size;
    if (shared) {
        links_.emplace(identity, relative_);
    }
    return true;
}

}
