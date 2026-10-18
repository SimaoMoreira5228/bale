#ifdef _WIN32

#include "extract/extractor.hpp"

#include "extract/windows_nt.hpp"

#include <algorithm>
#include <cstring>

namespace bale {

namespace nt {

namespace {

constexpr ULONG_PTR fileCreated = 2;
constexpr std::int64_t unixEpochTicks = 116'444'736'000'000'000;

}

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

bool isGone(const Error& error) {
    if (error.kind == ErrorKind::UnsafePath || error.kind == ErrorKind::AlreadyExists) {
        return true;
    }
    return error.kind == ErrorKind::Io &&
        (error.systemCode == ERROR_FILE_NOT_FOUND || error.systemCode == ERROR_PATH_NOT_FOUND);
}

Result<std::wstring_view> widen(std::string_view utf8, std::span<wchar_t> out) {
    const int count = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        utf8.data(),
        static_cast<int>(utf8.size()),
        out.data(),
        static_cast<int>(out.size() - 1)
    );
    if (count <= 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        return fail(ErrorKind::LimitExceeded, "name too long for the target");
    }
    if (count <= 0) {
        return fail(ErrorKind::UnsafePath, "path component is not valid UTF-8");
    }
    return std::wstring_view(out.data(), static_cast<std::size_t>(count));
}

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

Result<Extractor::FileId> fileIdOf(const OsHandle& handle) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle.get(), &info)) {
        return systemFailure(ErrorKind::Io, "cannot query file identity");
    }
    return Extractor::FileId{
        .device = info.dwVolumeSerialNumber,
        .inode = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow,
    };
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

}

using namespace nt;

namespace {

Result<void> syncHandle(const OsHandle& handle) {
    if (!FlushFileBuffers(handle.get())) {
        return systemFailure(ErrorKind::Io, "flush failed");
    }
    return {};
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

    // SECURITY: the Win32 rename wrapper resolves a full path; this call stays relative to the
    // parent handle.
    alignas(FILE_RENAME_INFO) std::array<std::byte, sizeof(FILE_RENAME_INFO) + sizeof(WideName)>
        buffer{};
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    info->ReplaceIfExists = replace ? TRUE : FALSE;
    info->RootDirectory = directory.get();
    info->FileNameLength = static_cast<DWORD>(name->size() * sizeof(wchar_t));
    std::memcpy(info->FileName, name->data(), name->size() * sizeof(wchar_t));

    const auto size = static_cast<ULONG>(sizeof(FILE_RENAME_INFO) + info->FileNameLength);
    IO_STATUS_BLOCK io{};
    NTSTATUS status = NtSetInformationFile(entry.get(), &io, info, size, fileRenameInformation);
    if (isSuccess(status)) {
        return EntryResult{};
    }
    if (status != statusNameCollision) {
        return statusFailure(ErrorKind::Io, "cannot move entry into place", status);
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

    if (policy_.restoreMtime && metadata.mtimeNanoseconds) {
        auto checked = toFileTime(*metadata.mtimeNanoseconds);
        if (!checked) {
            return std::unexpected(checked.error());
        }

        auto id = fileIdOf(opened.handle);
        if (!id) {
            return std::unexpected(id.error());
        }
        deferDirectoryTime(path, *id, *metadata.mtimeNanoseconds);
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

    auto id = fileIdOf(file.file_);
    if (!id) {
        return std::unexpected(id.error());
    }

    auto placed = place(file.directory_, file.file_, file.tempName_.data(), file.leaf());
    if (placed && placed->outcome == EntryOutcome::Extracted) {
        extractedFiles_.insert(*id);
    }
    return placed;
}

Result<void> Extractor::applyDeferredTime(std::string_view path, const DeferredTime& time) {
    auto parent = openParent(path, false);
    if (!parent) {
        if (isGone(parent.error())) {
            return {};
        }
        return std::unexpected(parent.error());
    }

    const std::size_t slash = path.rfind('/');
    WideName wide{};
    auto name = widen(slash == std::string_view::npos ? path : path.substr(slash + 1), wide);
    if (!name) {
        return std::unexpected(name.error());
    }

    auto opened = openRelative(
        parent->get(),
        *name,
        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        shareAll,
        FILE_OPEN,
        FILE_DIRECTORY_FILE
    );
    if (isMissing(opened.status) || opened.status == statusNotADirectory) {
        return {};
    }
    if (!isSuccess(opened.status)) {
        return statusFailure(ErrorKind::Io, "cannot reopen directory", opened.status);
    }

    auto attributes = attributesOf(opened.handle);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    auto id = fileIdOf(opened.handle);
    if (!id) {
        return std::unexpected(id.error());
    }
    if ((*attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || *id != time.id) {
        return {};
    }

    EntryMetadata metadata;
    metadata.mtimeNanoseconds = time.mtimeNanoseconds;
    return applyTimes(opened.handle, metadata, true);
}

}

#endif
