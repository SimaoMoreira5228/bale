#ifndef _WIN32

#include "extract/extractor.hpp"

#include "base/checked.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace bale {

namespace {

constexpr int directoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
constexpr int maxTempAttempts = 16;
constexpr std::int64_t nanosecondsPerSecond = 1'000'000'000;

std::unexpected<Error> systemFailure(ErrorKind kind, std::string_view what) {
    auto failure = fail(kind, what);
    failure.error().systemCode = errno;
    return failure;
}

int openAt(int directory, const char* name, int flags, mode_t mode = 0) {
    int fd = -1;
    do {
        fd = ::openat(directory, name, flags, mode);
    } while (fd < 0 && errno == EINTR);
    return fd;
}

[[nodiscard]] bool isNotDirectoryError(int error) {
    // NOTE: FreeBSD reports EMLINK where Linux reports ELOOP for O_NOFOLLOW on a symlink.
    return error == ELOOP || error == EMLINK || error == ENOTDIR;
}

std::unexpected<Error> componentFailure(int directory, const char* name) {
    const int error = errno;
    if (!isNotDirectoryError(error)) {
        return systemFailure(ErrorKind::Io, "cannot open directory in extraction path");
    }

    struct stat status{};
    if (::fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) == 0 && !S_ISLNK(status.st_mode)) {
        return fail(ErrorKind::AlreadyExists, "non-directory in extraction path");
    }
    return fail(ErrorKind::UnsafePath, "symlink in extraction path");
}

Result<OsHandle> openDirectoryAt(int directory, const char* name, bool create, mode_t mode) {
    int fd = openAt(directory, name, directoryFlags);
    if (fd < 0 && errno == ENOENT && create) {
        if (::mkdirat(directory, name, mode) != 0 && errno != EEXIST) {
            return systemFailure(ErrorKind::Io, "cannot create directory");
        }
        fd = openAt(directory, name, directoryFlags);
    }

    if (fd < 0) {
        return componentFailure(directory, name);
    }
    return OsHandle(fd);
}

Result<timespec> toTimespec(std::int64_t nanoseconds) {
    std::int64_t seconds = nanoseconds / nanosecondsPerSecond;
    std::int64_t remainder = nanoseconds % nanosecondsPerSecond;
    if (remainder < 0) {
        remainder += nanosecondsPerSecond;
        --seconds;
    }

    auto platformSeconds = checkedCast<time_t>(seconds);
    if (!platformSeconds) {
        return fail(ErrorKind::Unsupported, "modification time outside platform range");
    }

    timespec result{};
    result.tv_sec = *platformSeconds;
    result.tv_nsec = static_cast<long>(remainder);
    return result;
}

Result<void> applyTimes(int fd, const char* name, const EntryMetadata& metadata, bool restore) {
    if (!restore || !metadata.mtimeNanoseconds) {
        return {};
    }

    auto modified = toTimespec(*metadata.mtimeNanoseconds);
    if (!modified) {
        return std::unexpected(modified.error());
    }

    timespec times[2]{};
    times[0].tv_nsec = UTIME_OMIT;
    times[1] = *modified;

    const int status =
        name == nullptr ? ::futimens(fd, times) : ::utimensat(fd, name, times, AT_SYMLINK_NOFOLLOW);
    if (status != 0) {
        return systemFailure(ErrorKind::Io, "cannot set modification time");
    }
    return {};
}

Result<void> syncHandle(int fd) {
#ifdef __APPLE__
    // NOTE: plain fsync on macOS does not force the drive cache; F_FULLFSYNC does.
    if (::fcntl(fd, F_FULLFSYNC) == 0) {
        return {};
    }
#endif
    if (::fsync(fd) != 0) {
        return systemFailure(ErrorKind::Io, "fsync failed");
    }
    return {};
}

int renameNoReplace(int directory, const char* from, const char* to) {
#if defined(__linux__) && defined(RENAME_NOREPLACE)
    if (::renameat2(directory, from, directory, to, RENAME_NOREPLACE) == 0) {
        return 0;
    }
    if (errno != EINVAL && errno != ENOSYS && errno != EOPNOTSUPP) {
        return -1;
    }
#elif defined(__APPLE__)
    if (::renameatx_np(directory, from, directory, to, RENAME_EXCL) == 0) {
        return 0;
    }
    if (errno != EINVAL && errno != ENOTSUP) {
        return -1;
    }
#endif

    // NOTE: linking the new name fails atomically if it exists, giving no-replace semantics where
    // the filesystem lacks a no-replace rename.
    if (::linkat(directory, from, directory, to, 0) != 0) {
        return -1;
    }
    ::unlinkat(directory, from, 0);
    return 0;
}

[[nodiscard]] bool sameFile(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino;
}

[[nodiscard]] Extractor::FileId fileIdOf(const struct stat& status) {
    return Extractor::FileId{
        .device = static_cast<std::uint64_t>(status.st_dev),
        .inode = static_cast<std::uint64_t>(status.st_ino),
    };
}

[[nodiscard]] bool isGone(const Error& error) {
    if (error.kind == ErrorKind::UnsafePath || error.kind == ErrorKind::AlreadyExists) {
        return true;
    }
    return error.kind == ErrorKind::Io && error.systemCode == ENOENT;
}

}

void OsHandle::reset() {
    if (native_ != invalid) {
        ::close(native_);
        native_ = invalid;
    }
}

Result<Extractor>
Extractor::open(const std::filesystem::path& destinationRoot, const ExtractPolicy& policy) {
    int fd = -1;
    do {
        fd = ::open(destinationRoot.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        return systemFailure(ErrorKind::Io, "cannot open extraction root");
    }
    return Extractor(OsHandle(fd), policy);
}

Result<OsHandle> Extractor::openParent(std::string_view path, bool create) {
    const int duplicate = ::fcntl(root_.get(), F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) {
        return systemFailure(ErrorKind::Io, "cannot duplicate extraction root handle");
    }

    OsHandle current(duplicate);
    const auto mode = static_cast<mode_t>(directoryMode({}));
    std::size_t start = 0;
    for (std::size_t slash = path.find('/'); slash != std::string_view::npos;
         slash = path.find('/', start)) {
        component_.assign(path.substr(start, slash - start));

        auto next = openDirectoryAt(current.get(), component_.c_str(), create, mode);
        if (!next) {
            return std::unexpected(next.error());
        }

        current = std::move(*next);
        start = slash + 1;
    }
    return current;
}

Result<OsHandle> Extractor::openTemporary(const OsHandle& directory, TempName& name) {
    constexpr int flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC;
    for (int attempt = 0; attempt < maxTempAttempts; ++attempt) {
        nextTempName(name);

        const int fd = openAt(directory.get(), name.data(), flags, 0600);
        if (fd >= 0) {
            return OsHandle(fd);
        }
        if (errno != EEXIST) {
            return systemFailure(ErrorKind::Io, "cannot create temporary file");
        }
    }
    return fail(ErrorKind::Io, "cannot find a free temporary file name");
}

Result<void> Extractor::writeData(const OsHandle& file, std::span<const std::byte> data) {
    while (!data.empty()) {
        const ssize_t count = ::write(file.get(), data.data(), data.size());
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            return systemFailure(ErrorKind::Io, "write failed");
        }

        data = data.subspan(static_cast<std::size_t>(count));
    }
    return {};
}

void Extractor::removeTemporary(const OsHandle& directory, const OsHandle&, const char* tempName) {
    ::unlinkat(directory.get(), tempName, 0);
}

Result<EntryResult> Extractor::place(
    const OsHandle& directory,
    const OsHandle&,
    const char* tempName,
    std::string_view leaf
) {
    component_.assign(leaf);
    const char* name = component_.c_str();

    if (policy_.overwrite == OverwritePolicy::Replace) {
        struct stat status{};
        if (::fstatat(directory.get(), name, &status, AT_SYMLINK_NOFOLLOW) == 0 &&
            !S_ISREG(status.st_mode)) {
            return fail(ErrorKind::AlreadyExists, "existing target is not a regular file");
        }

        // SECURITY: renameat swaps the directory entry itself and never follows a symlink, so a
        // target changed after the check above is replaced, not written through. Renaming a
        // directory over it fails.
        if (::renameat(directory.get(), tempName, directory.get(), name) != 0) {
            if (errno == EISDIR || errno == ENOTEMPTY || errno == EEXIST) {
                return fail(ErrorKind::AlreadyExists, "existing target is not a regular file");
            }
            return systemFailure(ErrorKind::Io, "cannot move entry into place");
        }

        // NOTE: rename between two links to the same inode is a no-op that keeps the temporary.
        ::unlinkat(directory.get(), tempName, 0);
        return EntryResult{};
    }

    if (renameNoReplace(directory.get(), tempName, name) == 0) {
        return EntryResult{};
    }
    if (errno != EEXIST) {
        return systemFailure(ErrorKind::Io, "cannot move entry into place");
    }
    if (policy_.overwrite == OverwritePolicy::Skip) {
        return EntryResult{
            .outcome = EntryOutcome::Skipped,
            .reason = "target already exists",
        };
    }
    return fail(ErrorKind::AlreadyExists, "target already exists");
}

Result<EntryResult>
Extractor::createDirectory(const ArchivePath& path, const EntryMetadata& metadata) {
    auto entry = beginEntry(path);
    if (!entry) {
        return std::unexpected(entry.error());
    }

    auto parent = openParent(path.path, true);
    if (!parent) {
        return std::unexpected(parent.error());
    }

    component_.assign(entry->leaf);
    const char* name = component_.c_str();
    const bool created = ::mkdirat(parent->get(), name, 0700) == 0;
    if (!created && errno != EEXIST) {
        return systemFailure(ErrorKind::Io, "cannot create directory");
    }

    const int fd = openAt(parent->get(), name, directoryFlags);
    if (fd < 0) {
        if (created || !isNotDirectoryError(errno)) {
            return systemFailure(ErrorKind::Io, "cannot open directory");
        }
        if (policy_.overwrite == OverwritePolicy::Skip) {
            return EntryResult{
                .outcome = EntryOutcome::Skipped,
                .reason = "target exists and is not a directory",
            };
        }
        return fail(ErrorKind::AlreadyExists, "target exists and is not a directory");
    }

    OsHandle directory(fd);
    if (::fchmod(fd, static_cast<mode_t>(directoryMode(metadata))) != 0) {
        return systemFailure(ErrorKind::Io, "cannot set directory permissions");
    }

    if (policy_.restoreMtime && metadata.mtimeNanoseconds) {
        auto checked = toTimespec(*metadata.mtimeNanoseconds);
        if (!checked) {
            return std::unexpected(checked.error());
        }

        struct stat status{};
        if (::fstat(fd, &status) != 0) {
            return systemFailure(ErrorKind::Io, "cannot inspect directory");
        }
        deferDirectoryTime(path, fileIdOf(status), *metadata.mtimeNanoseconds);
    }

    if (policy_.durable && created) {
        auto synced = syncHandle(parent->get());
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }
    return EntryResult{};
}

Result<PendingFile> Extractor::beginFile(const ArchivePath& path, const EntryMetadata& metadata) {
    auto entry = beginEntry(path);
    if (!entry) {
        return std::unexpected(entry.error());
    }

    auto parent = openParent(path.path, true);
    if (!parent) {
        return std::unexpected(parent.error());
    }

    PendingFile pending(*this);
    pending.metadata_ = metadata;
    std::memcpy(pending.leaf_.data(), entry->leaf.data(), entry->leaf.size());
    pending.leaf_[entry->leaf.size()] = '\0';
    pending.leafSize_ = entry->leaf.size();

    struct stat status{};
    if (::fstatat(parent->get(), pending.leaf_.data(), &status, AT_SYMLINK_NOFOLLOW) == 0) {
        if (policy_.overwrite == OverwritePolicy::Never) {
            return fail(ErrorKind::AlreadyExists, "target already exists");
        }
        if (policy_.overwrite == OverwritePolicy::Skip) {
            pending.state_ = PendingFile::State::Skipping;
            return pending;
        }
        if (!S_ISREG(status.st_mode)) {
            return fail(ErrorKind::AlreadyExists, "existing target is not a regular file");
        }
    } else if (errno != ENOENT) {
        return systemFailure(ErrorKind::Io, "cannot inspect extraction target");
    }

    auto file = openTemporary(*parent, pending.tempName_);
    if (!file) {
        return std::unexpected(file.error());
    }

    pending.directory_ = std::move(*parent);
    pending.file_ = std::move(*file);
    return pending;
}

Result<EntryResult> Extractor::finishFile(PendingFile& file) {
    const int fd = file.file_.get();
    if (::fchmod(fd, static_cast<mode_t>(fileMode(file.metadata_))) != 0) {
        return systemFailure(ErrorKind::Io, "cannot set file permissions");
    }

    auto times = applyTimes(fd, nullptr, file.metadata_, policy_.restoreMtime);
    if (!times) {
        return std::unexpected(times.error());
    }

    if (policy_.durable) {
        auto synced = syncHandle(fd);
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }

    struct stat status{};
    if (::fstat(fd, &status) != 0) {
        return systemFailure(ErrorKind::Io, "cannot inspect extracted file");
    }

    auto placed = place(file.directory_, file.file_, file.tempName_.data(), file.leaf());
    if (!placed || placed->outcome == EntryOutcome::Skipped) {
        return placed;
    }

    extractedFiles_.insert(fileIdOf(status));

    if (policy_.durable) {
        auto synced = syncHandle(file.directory_.get());
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }
    return placed;
}

Result<EntryResult> Extractor::createSymlink(
    const ArchivePath& path,
    std::string_view target,
    const EntryMetadata& metadata
) {
    auto entry = beginEntry(path);
    if (!entry) {
        return std::unexpected(entry.error());
    }

    if (policy_.symlinks == SymlinkPolicy::Refuse) {
        return fail(ErrorKind::UnsafePath, "symlink entries are refused");
    }
    if (policy_.symlinks == SymlinkPolicy::Skip) {
        return EntryResult{
            .outcome = EntryOutcome::Skipped,
            .reason = "symlink entries are skipped by policy",
        };
    }

    auto normalized = normalizeLinkTarget(target, entry->parentDepth);
    if (!normalized) {
        return std::unexpected(normalized.error());
    }

    auto parent = openParent(path.path, true);
    if (!parent) {
        return std::unexpected(parent.error());
    }

    TempName tempName{};
    bool linked = false;
    for (int attempt = 0; attempt < maxTempAttempts && !linked; ++attempt) {
        nextTempName(tempName);
        linked = ::symlinkat(linkTarget_.c_str(), parent->get(), tempName.data()) == 0;
        if (!linked && errno != EEXIST) {
            return systemFailure(ErrorKind::Io, "cannot create symlink");
        }
    }
    if (!linked) {
        return fail(ErrorKind::Io, "cannot find a free temporary file name");
    }

    auto times = applyTimes(parent->get(), tempName.data(), metadata, policy_.restoreMtime);
    auto placed = times ? place(*parent, OsHandle{}, tempName.data(), entry->leaf)
                        : Result<EntryResult>(std::unexpected(times.error()));
    if (!placed || placed->outcome == EntryOutcome::Skipped) {
        ::unlinkat(parent->get(), tempName.data(), 0);
        return placed;
    }

    if (policy_.durable) {
        auto synced = syncHandle(parent->get());
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }
    return placed;
}

Result<EntryResult>
Extractor::createHardLink(const ArchivePath& path, const ArchivePath& existingPath) {
    auto entry = beginEntry(path);
    if (!entry) {
        return std::unexpected(entry.error());
    }

    if (policy_.hardLinks == HardLinkPolicy::Refuse) {
        return fail(ErrorKind::UnsafePath, "hard link entries are refused");
    }

    auto source = splitPath(existingPath.path);
    if (!source) {
        return std::unexpected(source.error());
    }

    auto sourceParent = openParent(existingPath.path, false);
    if (!sourceParent) {
        if (sourceParent.error().kind == ErrorKind::Io &&
            sourceParent.error().systemCode == ENOENT) {
            return fail(
                ErrorKind::UnsafePath,
                "hard link target was not extracted in this session"
            );
        }
        return std::unexpected(sourceParent.error());
    }

    std::array<char, maxLeafBytes + 1> sourceName{};
    std::memcpy(sourceName.data(), source->leaf.data(), source->leaf.size());

    struct stat sourceStatus{};
    if (::fstatat(sourceParent->get(), sourceName.data(), &sourceStatus, AT_SYMLINK_NOFOLLOW) !=
        0) {
        if (errno == ENOENT) {
            return fail(
                ErrorKind::UnsafePath,
                "hard link target was not extracted in this session"
            );
        }
        return systemFailure(ErrorKind::Io, "cannot inspect hard link target");
    }
    if (!S_ISREG(sourceStatus.st_mode)) {
        return fail(ErrorKind::UnsafePath, "hard link target is not a regular file");
    }

    if (!extractedFiles_.contains(fileIdOf(sourceStatus))) {
        return fail(ErrorKind::UnsafePath, "hard link target was not extracted in this session");
    }

    auto parent = openParent(path.path, true);
    if (!parent) {
        return std::unexpected(parent.error());
    }

    TempName tempName{};
    bool linked = false;
    for (int attempt = 0; attempt < maxTempAttempts && !linked; ++attempt) {
        nextTempName(tempName);
        linked =
            ::linkat(sourceParent->get(), sourceName.data(), parent->get(), tempName.data(), 0) ==
            0;
        if (!linked && errno != EEXIST) {
            return systemFailure(ErrorKind::Io, "cannot create hard link");
        }
    }
    if (!linked) {
        return fail(ErrorKind::Io, "cannot find a free temporary file name");
    }

    // SECURITY: the source name may have been swapped between the check and linkat, so the new
    // link itself is verified to be the extracted inode before it is moved into place.
    struct stat linkStatus{};
    if (::fstatat(parent->get(), tempName.data(), &linkStatus, AT_SYMLINK_NOFOLLOW) != 0 ||
        !sameFile(linkStatus, sourceStatus)) {
        ::unlinkat(parent->get(), tempName.data(), 0);
        return fail(ErrorKind::UnsafePath, "hard link target changed during extraction");
    }

    auto placed = place(*parent, OsHandle{}, tempName.data(), entry->leaf);
    if (!placed || placed->outcome == EntryOutcome::Skipped) {
        ::unlinkat(parent->get(), tempName.data(), 0);
        return placed;
    }

    if (policy_.durable) {
        auto synced = syncHandle(parent->get());
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }
    return placed;
}

Result<void> Extractor::applyDeferredTime(std::string_view path, const DeferredTime& time) {
    // SECURITY: the directory is reached again component by component with O_NOFOLLOW from the
    // root, and its device and inode must match the directory created earlier, so a directory
    // swapped for a symlink or another directory after extraction is left alone.
    auto parent = openParent(path, false);
    if (!parent) {
        if (isGone(parent.error())) {
            return {};
        }
        return std::unexpected(parent.error());
    }

    const std::size_t slash = path.rfind('/');
    component_.assign(slash == std::string_view::npos ? path : path.substr(slash + 1));
    const int fd = openAt(parent->get(), component_.c_str(), directoryFlags);
    if (fd < 0) {
        if (errno == ENOENT || isNotDirectoryError(errno)) {
            return {};
        }
        return systemFailure(ErrorKind::Io, "cannot reopen directory");
    }

    OsHandle directory(fd);
    struct stat status{};
    if (::fstat(fd, &status) != 0) {
        return systemFailure(ErrorKind::Io, "cannot inspect directory");
    }
    if (fileIdOf(status) != time.id) {
        return {};
    }

    EntryMetadata metadata;
    metadata.mtimeNanoseconds = time.mtimeNanoseconds;
    return applyTimes(fd, nullptr, metadata, true);
}

}

#endif
