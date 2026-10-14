#ifdef _WIN32

#include "base/endian.hpp"
#include "extract/windows_nt.hpp"

#include <algorithm>
#include <cstring>

#include <winioctl.h>

namespace bale {

using namespace nt;

namespace {

constexpr std::uint32_t symlinkReparseTag = 0xA000000C;
constexpr std::uint32_t symlinkFlagRelative = 1;
constexpr std::size_t reparseHeaderBytes = 8;
constexpr std::size_t symlinkHeaderBytes = reparseHeaderBytes + 12;
constexpr std::size_t maxReparseBytes = std::size_t{16} * 1024;
constexpr std::size_t maxTargetUnits = (maxReparseBytes - symlinkHeaderBytes) / 4;

using ReparseBuffer = std::array<std::byte, maxReparseBytes>;
using WideTarget = std::array<wchar_t, maxTargetUnits + 1>;

Result<std::size_t> buildSymlinkReparse(std::string_view target, ReparseBuffer& buffer) {
    WideTarget wide{};
    auto converted = widen(target, wide);
    if (!converted) {
        return std::unexpected(converted.error());
    }
    std::replace(wide.begin(), wide.begin() + converted->size(), L'/', L'\\');

    const std::size_t nameBytes = converted->size() * sizeof(wchar_t);
    const std::size_t dataBytes = symlinkHeaderBytes - reparseHeaderBytes + 2 * nameBytes;
    std::byte* out = buffer.data();
    storeLe<std::uint32_t>(out, symlinkReparseTag);
    storeLe<std::uint16_t>(out + 4, static_cast<std::uint16_t>(dataBytes));
    storeLe<std::uint16_t>(out + 6, 0);
    storeLe<std::uint16_t>(out + 8, 0);
    storeLe<std::uint16_t>(out + 10, static_cast<std::uint16_t>(nameBytes));
    storeLe<std::uint16_t>(out + 12, static_cast<std::uint16_t>(nameBytes));
    storeLe<std::uint16_t>(out + 14, static_cast<std::uint16_t>(nameBytes));
    storeLe<std::uint32_t>(out + 16, symlinkFlagRelative);
    std::memcpy(out + symlinkHeaderBytes, wide.data(), nameBytes);
    std::memcpy(out + symlinkHeaderBytes + nameBytes, wide.data(), nameBytes);
    return reparseHeaderBytes + dataBytes;
}

std::string_view leafOf(std::string_view path) {
    const std::size_t slash = path.rfind('/');
    return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

std::string_view
resolveTarget(std::string_view entryPath, std::string_view target, std::string& out) {
    const std::size_t entrySlash = entryPath.rfind('/');
    std::string_view base =
        entrySlash == std::string_view::npos ? std::string_view{} : entryPath.substr(0, entrySlash);

    while (target == ".." || target.starts_with("../")) {
        const std::size_t slash = base.rfind('/');
        base = slash == std::string_view::npos ? std::string_view{} : base.substr(0, slash);
        target.remove_prefix(std::min<std::size_t>(target.size(), 3));
    }
    if (target == ".") {
        target = {};
    }

    out.assign(base);
    if (!out.empty() && !target.empty()) {
        out.push_back('/');
    }
    out.append(target);
    return out;
}

bool isDirectoryLeaf(const OsHandle& parent, std::string_view leaf) {
    WideName wide{};
    auto name = widen(leaf, wide);
    if (!name) {
        return false;
    }

    auto opened = openRelative(parent.get(), *name, FILE_READ_ATTRIBUTES, shareAll, FILE_OPEN, 0);
    if (!isSuccess(opened.status)) {
        return false;
    }

    auto attributes = attributesOf(opened.handle);
    return attributes && (*attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
        (*attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0;
}

void deleteByHandle(const OsHandle& handle) {
    FILE_DISPOSITION_INFO disposition{};
    disposition.DeleteFile = TRUE;
    SetFileInformationByHandle(
        handle.get(),
        FileDispositionInfo,
        &disposition,
        sizeof(disposition)
    );
}

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

    ReparseBuffer reparse{};
    auto reparseSize = buildSymlinkReparse(*normalized, reparse);
    if (!reparseSize) {
        return std::unexpected(reparseSize.error());
    }

    auto resolved = resolveTarget(path.path, *normalized, component_);
    bool directory = resolved.empty();
    if (!directory) {
        auto targetParent = openParent(resolved, false);
        directory = targetParent && isDirectoryLeaf(*targetParent, leafOf(resolved));
    }

    auto parent = openParent(path.path, true);
    if (!parent) {
        return std::unexpected(parent.error());
    }

    TempName tempName{};
    WideName wide{};
    Opened link;
    for (int attempt = 0; attempt < maxTempAttempts; ++attempt) {
        nextTempName(tempName);
        auto name = widen(tempName.data(), wide);
        if (!name) {
            return std::unexpected(name.error());
        }

        link = openRelative(
            parent->get(),
            *name,
            FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE,
            0,
            FILE_CREATE,
            directory ? FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE
        );
        if (link.status != statusNameCollision) {
            break;
        }
    }
    if (link.status == statusNameCollision) {
        return fail(ErrorKind::Io, "cannot find a free temporary file name");
    }
    if (!isSuccess(link.status)) {
        return statusFailure(ErrorKind::Io, "cannot create symlink", link.status);
    }

    DWORD returned = 0;
    if (!DeviceIoControl(
            link.handle.get(),
            FSCTL_SET_REPARSE_POINT,
            reparse.data(),
            static_cast<DWORD>(*reparseSize),
            nullptr,
            0,
            &returned,
            nullptr
        )) {
        const DWORD error = GetLastError();
        deleteByHandle(link.handle);
        if (error == ERROR_PRIVILEGE_NOT_HELD) {
            return fail(
                ErrorKind::Unsupported,
                "creating symlinks on Windows needs Developer Mode or the symbolic link privilege"
            );
        }

        auto failure = fail(ErrorKind::Io, "cannot set symlink reparse point");
        failure.error().systemCode = static_cast<int>(error);
        return failure;
    }

    auto times = applyTimes(link.handle, metadata, policy_.restoreMtime);
    auto placed = times ? place(*parent, link.handle, tempName.data(), entry->leaf)
                        : Result<EntryResult>(std::unexpected(times.error()));
    if (!placed || placed->outcome == EntryOutcome::Skipped) {
        deleteByHandle(link.handle);
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
        if (isGone(sourceParent.error()) && sourceParent.error().kind == ErrorKind::Io) {
            return fail(
                ErrorKind::UnsafePath,
                "hard link target was not extracted in this session"
            );
        }
        return std::unexpected(sourceParent.error());
    }

    WideName wide{};
    auto sourceName = widen(source->leaf, wide);
    if (!sourceName) {
        return std::unexpected(sourceName.error());
    }

    auto opened = openRelative(
        sourceParent->get(),
        *sourceName,
        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
        shareAll,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE
    );
    if (isMissing(opened.status)) {
        return fail(ErrorKind::UnsafePath, "hard link target was not extracted in this session");
    }
    if (opened.status == statusFileIsADirectory) {
        return fail(ErrorKind::UnsafePath, "hard link target is not a regular file");
    }
    if (!isSuccess(opened.status)) {
        return statusFailure(ErrorKind::Io, "cannot open hard link target", opened.status);
    }

    auto attributes = attributesOf(opened.handle);
    if (!attributes) {
        return std::unexpected(attributes.error());
    }
    if ((*attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        return fail(ErrorKind::UnsafePath, "hard link target is not a regular file");
    }

    auto sourceId = fileIdOf(opened.handle);
    if (!sourceId) {
        return std::unexpected(sourceId.error());
    }
    if (!extractedFiles_.contains(*sourceId)) {
        return fail(ErrorKind::UnsafePath, "hard link target was not extracted in this session");
    }

    auto parent = openParent(path.path, true);
    if (!parent) {
        return std::unexpected(parent.error());
    }

    // WORKAROUND: Wine silently succeeds when renaming one link of a file over another link of the
    // same file, so the destination is checked first.
    if (policy_.overwrite != OverwritePolicy::Replace) {
        auto leafName = widen(entry->leaf, wide);
        if (!leafName) {
            return std::unexpected(leafName.error());
        }

        auto existing =
            openRelative(parent->get(), *leafName, FILE_READ_ATTRIBUTES, shareAll, FILE_OPEN, 0);
        if (isSuccess(existing.status) && policy_.overwrite == OverwritePolicy::Skip) {
            return EntryResult{
                .outcome = EntryOutcome::Skipped,
                .reason = "target already exists",
            };
        }
        if (isSuccess(existing.status)) {
            return fail(ErrorKind::AlreadyExists, "target already exists");
        }
    }

    alignas(FILE_RENAME_INFO) std::array<std::byte, sizeof(FILE_RENAME_INFO) + sizeof(WideName)>
        buffer{};
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    TempName tempName{};
    std::wstring_view tempWide;
    NTSTATUS status = statusNameCollision;
    for (int attempt = 0; attempt < maxTempAttempts && status == statusNameCollision; ++attempt) {
        nextTempName(tempName);
        auto name = widen(tempName.data(), wide);
        if (!name) {
            return std::unexpected(name.error());
        }

        tempWide = *name;
        info->ReplaceIfExists = FALSE;
        info->RootDirectory = parent->get();
        info->FileNameLength = static_cast<DWORD>(name->size() * sizeof(wchar_t));
        std::memcpy(info->FileName, name->data(), name->size() * sizeof(wchar_t));

        const auto size = static_cast<ULONG>(sizeof(FILE_RENAME_INFO) + info->FileNameLength);
        IO_STATUS_BLOCK io{};
        status = NtSetInformationFile(opened.handle.get(), &io, info, size, fileLinkInformation);
    }
    if (status == statusNameCollision) {
        return fail(ErrorKind::Io, "cannot find a free temporary file name");
    }
    if (!isSuccess(status)) {
        return statusFailure(ErrorKind::Io, "cannot create hard link", status);
    }

    auto linked = openRelative(
        parent->get(),
        tempWide,
        FILE_READ_ATTRIBUTES | DELETE,
        shareAll,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE
    );
    if (!isSuccess(linked.status)) {
        return statusFailure(ErrorKind::Io, "cannot reopen new hard link", linked.status);
    }

    auto linkedId = fileIdOf(linked.handle);
    if (!linkedId || *linkedId != *sourceId) {
        return fail(ErrorKind::UnsafePath, "hard link target changed during extraction");
    }

    auto placed = place(*parent, linked.handle, tempName.data(), entry->leaf);
    if (!placed || placed->outcome == EntryOutcome::Skipped) {
        deleteByHandle(linked.handle);
    }
    return placed;
}

}

#endif
