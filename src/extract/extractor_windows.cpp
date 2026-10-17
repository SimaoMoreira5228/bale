#ifdef _WIN32

#include "extract/extractor.hpp"

#include <algorithm>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>

#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_CREATE
#define FILE_CREATE 0x00000002
#endif
#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF 0x00000003
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_OPEN_REPARSE_POINT
#define FILE_OPEN_REPARSE_POINT 0x00200000
#endif

namespace bale {

namespace {

// SECURITY: every component is opened with NtCreateFile relative to the handle of its already
// verified parent, with FILE_OPEN_REPARSE_POINT so junctions and symlinks are opened rather than
// followed and then refused. No full path is ever resolved after the root, so there is no window
// in which a swapped component could redirect the walk.

using WideName = std::array<wchar_t, maxLeafBytes + 1>;

constexpr NTSTATUS statusNameNotFound = static_cast<NTSTATUS>(0xC0000034L);
constexpr NTSTATUS statusNameCollision = static_cast<NTSTATUS>(0xC0000035L);
constexpr NTSTATUS statusPathNotFound = static_cast<NTSTATUS>(0xC000003AL);
constexpr NTSTATUS statusNotADirectory = static_cast<NTSTATUS>(0xC0000103L);
constexpr NTSTATUS statusFileIsADirectory = static_cast<NTSTATUS>(0xC00000BAL);
constexpr ULONG_PTR fileCreated = 2;
constexpr ULONG shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
constexpr ACCESS_MASK directoryAccess = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES |
    FILE_WRITE_ATTRIBUTES | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;
constexpr int maxTempAttempts = 16;
constexpr std::int64_t unixEpochTicks = 116'444'736'000'000'000;

std::unexpected<Error> systemFailure(ErrorKind kind, std::string_view what) {
    auto failure = fail(kind, what);
    failure.error().systemCode = static_cast<int>(GetLastError());
    return failure;
}

std::unexpected<Error> statusFailure(ErrorKind kind, std::string_view what, NTSTATUS status) {
    auto failure = fail(kind, what);
    failure.error().systemCode = static_cast<int>(RtlNtStatusToDosError(status));
    return failure;
}

[[nodiscard]] bool isSuccess(NTSTATUS status) {
    return status >= 0;
}

[[nodiscard]] bool isMissing(NTSTATUS status) {
    return status == statusNameNotFound || status == statusPathNotFound;
}

Result<std::wstring_view> widen(std::string_view utf8, WideName& out) {
    const int count = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        utf8.data(),
        static_cast<int>(utf8.size()),
        out.data(),
        static_cast<int>(out.size() - 1)
    );
    if (count <= 0) {
        return fail(ErrorKind::UnsafePath, "path component is not valid UTF-8");
    }
    return std::wstring_view(out.data(), static_cast<std::size_t>(count));
}

struct Opened {
    NTSTATUS status = 0;
    OsHandle handle;
    bool created = false;
};

Opened openRelative(
    HANDLE parent,
    std::wstring_view name,
    ACCESS_MASK access,
    ULONG share,
    ULONG disposition,
    ULONG options
) {
    UNICODE_STRING unicode{};
    unicode.Buffer = const_cast<PWSTR>(name.data());
    unicode.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
    unicode.MaximumLength = unicode.Length;

    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &unicode, OBJ_CASE_INSENSITIVE, parent, nullptr);

    IO_STATUS_BLOCK io{};
    HANDLE handle = nullptr;
    Opened result;
    result.status = NtCreateFile(
        &handle,
        access | SYNCHRONIZE,
        &attributes,
        &io,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        share,
        disposition,
        options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        nullptr,
        0
    );
    if (isSuccess(result.status)) {
        result.handle = OsHandle(handle);
        result.created = io.Information == fileCreated;
    }
    return result;
}

Result<DWORD> attributesOf(const OsHandle& handle) {
    FILE_ATTRIBUTE_TAG_INFO info{};
    if (!GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &info, sizeof(info))) {
        return systemFailure(ErrorKind::Io, "cannot query file attributes");
    }
    return info.FileAttributes;
}

Result<OsHandle> openDirectoryAt(HANDLE parent, std::wstring_view name, bool create) {
    auto opened = openRelative(
        parent,
        name,
        directoryAccess,
        shareAll,
        create ? FILE_OPEN_IF : FILE_OPEN,
        FILE_DIRECTORY_FILE
    );
    if (opened.status == statusNotADirectory) {
        return fail(ErrorKind::AlreadyExists, "non-directory in extraction path");
    }
    if (!isSuccess(opened.status)) {
        return statusFailure(
            ErrorKind::Io,
            "cannot open directory in extraction path",
            opened.status
        );
    }

    auto attributes = attributesOf(opened.handle);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    if ((*attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return fail(ErrorKind::UnsafePath, "reparse point in extraction path");
    }
    return std::move(opened.handle);
}

Result<FILETIME> toFileTime(std::int64_t nanoseconds) {
    std::int64_t ticks = nanoseconds / 100;
    if (nanoseconds % 100 < 0) {
        --ticks;
    }

    ticks += unixEpochTicks;
    if (ticks < 0) {
        return fail(ErrorKind::Unsupported, "modification time outside platform range");
    }

    const auto value = static_cast<std::uint64_t>(ticks);
    FILETIME result{};
    result.dwLowDateTime = static_cast<DWORD>(value);
    result.dwHighDateTime = static_cast<DWORD>(value >> 32);
    return result;
}

Result<void> applyTimes(const OsHandle& handle, const EntryMetadata& metadata, bool restore) {
    if (!restore || !metadata.mtimeNanoseconds) {
        return {};
    }

    auto modified = toFileTime(*metadata.mtimeNanoseconds);
    if (!modified) {
        return std::unexpected(modified.error());
    }
    if (!SetFileTime(handle.get(), nullptr, nullptr, &*modified)) {
        return systemFailure(ErrorKind::Io, "cannot set modification time");
    }
    return {};
}

Result<void> syncHandle(const OsHandle& handle) {
    if (!FlushFileBuffers(handle.get())) {
        return systemFailure(ErrorKind::Io, "flush failed");
    }
    return {};
}

}

void OsHandle::reset() {
    if (native_ != invalid) {
        CloseHandle(native_);
        native_ = invalid;
    }
}

Result<Extractor>
Extractor::open(const std::filesystem::path& destinationRoot, const ExtractPolicy& policy) {
    HANDLE handle = CreateFileW(
        destinationRoot.c_str(),
        directoryAccess | SYNCHRONIZE,
        shareAll,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return systemFailure(ErrorKind::Io, "cannot open extraction root");
    }

    OsHandle root(handle);
    auto attributes = attributesOf(root);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    if ((*attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        return fail(ErrorKind::Io, "extraction root is not a directory");
    }
    return Extractor(std::move(root), policy);
}

Result<OsHandle> Extractor::openParent(std::string_view path, bool create) {
    HANDLE duplicate = nullptr;
    if (!DuplicateHandle(
            GetCurrentProcess(),
            root_.get(),
            GetCurrentProcess(),
            &duplicate,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS
        )) {
        return systemFailure(ErrorKind::Io, "cannot duplicate extraction root handle");
    }

    OsHandle current(duplicate);
    WideName wide{};
    std::size_t start = 0;
    for (std::size_t slash = path.find('/'); slash != std::string_view::npos;
         slash = path.find('/', start)) {
        auto name = widen(path.substr(start, slash - start), wide);
        if (!name) {
            return std::unexpected(name.error());
        }

        auto next = openDirectoryAt(current.get(), *name, create);
        if (!next) {
            return std::unexpected(next.error());
        }

        current = std::move(*next);
        start = slash + 1;
    }
    return current;
}

Result<OsHandle> Extractor::openTemporary(const OsHandle& directory, TempName& name) {
    WideName wide{};
    for (int attempt = 0; attempt < maxTempAttempts; ++attempt) {
        nextTempName(name);

        auto wideName = widen(name.data(), wide);
        if (!wideName) {
            return std::unexpected(wideName.error());
        }

        auto opened = openRelative(
            directory.get(),
            *wideName,
            GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
            0,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE
        );
        if (isSuccess(opened.status)) {
            return std::move(opened.handle);
        }
        if (opened.status != statusNameCollision) {
            return statusFailure(ErrorKind::Io, "cannot create temporary file", opened.status);
        }
    }
    return fail(ErrorKind::Io, "cannot find a free temporary file name");
}

Result<void> Extractor::writeData(const OsHandle& file, std::span<const std::byte> data) {
    while (!data.empty()) {
        auto request = static_cast<DWORD>(std::min<std::size_t>(data.size(), MAXDWORD));
        DWORD count = 0;
        if (!WriteFile(file.get(), data.data(), request, &count, nullptr)) {
            return systemFailure(ErrorKind::Io, "write failed");
        }

        data = data.subspan(count);
    }
    return {};
}

void Extractor::removeTemporary(const OsHandle&, const OsHandle& file, const char*) {
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition, sizeof(disposition));
}

Result<EntryResult> Extractor::place(
    const OsHandle& directory,
    const OsHandle& entry,
    const char*,
    std::string_view leaf
) {
    WideName wide{};
    auto name = widen(leaf, wide);
    if (!name) {
        return std::unexpected(name.error());
    }

    const bool replace = policy_.overwrite == OverwritePolicy::Replace;
    if (replace) {
        auto existing =
            openRelative(directory.get(), *name, FILE_READ_ATTRIBUTES, shareAll, FILE_OPEN, 0);
        if (isSuccess(existing.status)) {
            auto attributes = attributesOf(existing.handle);
            if (!attributes) {
                return std::unexpected(attributes.error());
            }
            if ((*attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
                return fail(ErrorKind::AlreadyExists, "existing target is not a regular file");
            }
        } else if (!isMissing(existing.status)) {
            return statusFailure(
                ErrorKind::Io,
                "cannot inspect extraction target",
                existing.status
            );
        }
    }

    // SECURITY: the rename is relative to the parent handle, so it never resolves a path. With
    // ReplaceIfExists the check above can race with a swap to a reparse point, but the rename then
    // replaces the reparse point itself rather than writing through it, and renaming over a
    // directory fails.
    alignas(FILE_RENAME_INFO) std::array<std::byte, sizeof(FILE_RENAME_INFO) + sizeof(WideName)>
        buffer{};
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    info->ReplaceIfExists = replace ? TRUE : FALSE;
    info->RootDirectory = directory.get();
    info->FileNameLength = static_cast<DWORD>(name->size() * sizeof(wchar_t));
    std::memcpy(info->FileName, name->data(), name->size() * sizeof(wchar_t));

    const auto size = static_cast<DWORD>(sizeof(FILE_RENAME_INFO) + info->FileNameLength);
    if (SetFileInformationByHandle(entry.get(), FileRenameInfo, info, size)) {
        return EntryResult{};
    }

    const DWORD error = GetLastError();
    if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS) {
        return systemFailure(ErrorKind::Io, "cannot move entry into place");
    }
    if (replace) {
        return fail(ErrorKind::AlreadyExists, "existing target is not a regular file");
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

    WideName wide{};
    auto name = widen(entry->leaf, wide);
    if (!name) {
        return std::unexpected(name.error());
    }

    auto opened = openRelative(
        parent->get(),
        *name,
        directoryAccess,
        shareAll,
        FILE_OPEN_IF,
        FILE_DIRECTORY_FILE
    );
    if (opened.status == statusNotADirectory) {
        if (policy_.overwrite == OverwritePolicy::Skip) {
            return EntryResult{
                .outcome = EntryOutcome::Skipped,
                .reason = "target exists and is not a directory",
            };
        }
        return fail(ErrorKind::AlreadyExists, "target exists and is not a directory");
    }
    if (!isSuccess(opened.status)) {
        return statusFailure(ErrorKind::Io, "cannot create directory", opened.status);
    }

    auto attributes = attributesOf(opened.handle);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    if ((*attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        return fail(ErrorKind::UnsafePath, "reparse point at extraction target");
    }

    // NOTE: Windows has no POSIX permission bits; the mode is not restored there.
    auto times = applyTimes(opened.handle, metadata, policy_.restoreMtime);
    if (!times) {
        return std::unexpected(times.error());
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

    WideName wide{};
    auto name = widen(entry->leaf, wide);
    if (!name) {
        return std::unexpected(name.error());
    }

    PendingFile pending(*this);
    pending.metadata_ = metadata;
    std::memcpy(pending.leaf_.data(), entry->leaf.data(), entry->leaf.size());
    pending.leaf_[entry->leaf.size()] = '\0';
    pending.leafSize_ = entry->leaf.size();

    auto existing =
        openRelative(parent->get(), *name, FILE_READ_ATTRIBUTES, shareAll, FILE_OPEN, 0);
    if (isSuccess(existing.status)) {
        if (policy_.overwrite == OverwritePolicy::Never) {
            return fail(ErrorKind::AlreadyExists, "target already exists");
        }
        if (policy_.overwrite == OverwritePolicy::Skip) {
            pending.state_ = PendingFile::State::Skipping;
            return pending;
        }

        auto attributes = attributesOf(existing.handle);
        if (!attributes) {
            return std::unexpected(attributes.error());
        }
        if ((*attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
            return fail(ErrorKind::AlreadyExists, "existing target is not a regular file");
        }
    } else if (!isMissing(existing.status) && existing.status != statusFileIsADirectory) {
        return statusFailure(ErrorKind::Io, "cannot inspect extraction target", existing.status);
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
    // NOTE: Windows has no POSIX permission bits; the mode is not restored there.
    auto times = applyTimes(file.file_, file.metadata_, policy_.restoreMtime);
    if (!times) {
        return std::unexpected(times.error());
    }

    if (policy_.durable) {
        auto synced = syncHandle(file.file_);
        if (!synced) {
            return std::unexpected(synced.error());
        }
    }

    return place(file.directory_, file.file_, file.tempName_.data(), file.leaf());
}

Result<EntryResult>
Extractor::createSymlink(const ArchivePath& path, std::string_view target, const EntryMetadata&) {
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

    // TODO: create the link relative to the parent handle (NtCreateFile plus
    // FSCTL_SET_REPARSE_POINT), which also needs SeCreateSymbolicLinkPrivilege or developer mode.
    return fail(ErrorKind::Unsupported, "symlink extraction is not implemented on Windows");
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

    // TODO: link relative to the parent handle with FileLinkInformation and track extracted file
    // identities (volume serial plus file index) as the POSIX side does.
    return fail(ErrorKind::Unsupported, "hard link extraction is not implemented on Windows");
}

}

#endif
