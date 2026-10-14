#pragma once

#ifdef _WIN32

#include "extract/extractor.hpp"

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

#ifdef _MSC_VER
extern "C" NTSTATUS NTAPI NtSetInformationFile(
    HANDLE file,
    PIO_STATUS_BLOCK status,
    PVOID information,
    ULONG length,
    FILE_INFORMATION_CLASS informationClass
);
#endif

namespace bale::nt {

using WideName = std::array<wchar_t, maxLeafBytes + 1>;

inline constexpr NTSTATUS statusNameNotFound = static_cast<NTSTATUS>(0xC0000034L);
inline constexpr NTSTATUS statusNameCollision = static_cast<NTSTATUS>(0xC0000035L);
inline constexpr NTSTATUS statusPathNotFound = static_cast<NTSTATUS>(0xC000003AL);
inline constexpr NTSTATUS statusNotADirectory = static_cast<NTSTATUS>(0xC0000103L);
inline constexpr NTSTATUS statusFileIsADirectory = static_cast<NTSTATUS>(0xC00000BAL);
inline constexpr auto fileRenameInformation = static_cast<FILE_INFORMATION_CLASS>(10);
inline constexpr auto fileLinkInformation = static_cast<FILE_INFORMATION_CLASS>(11);
inline constexpr ULONG shareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
inline constexpr ACCESS_MASK directoryAccess = FILE_LIST_DIRECTORY | FILE_TRAVERSE |
    FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;
inline constexpr int maxTempAttempts = 16;

struct Opened {
    NTSTATUS status = 0;
    OsHandle handle;
    bool created = false;
};

[[nodiscard]] std::unexpected<Error> systemFailure(ErrorKind kind, std::string_view what);

[[nodiscard]] std::unexpected<Error>
statusFailure(ErrorKind kind, std::string_view what, NTSTATUS status);

[[nodiscard]] inline bool isSuccess(NTSTATUS status) {
    return status >= 0;
}

[[nodiscard]] inline bool isMissing(NTSTATUS status) {
    return status == statusNameNotFound || status == statusPathNotFound;
}

[[nodiscard]] bool isGone(const Error& error);

[[nodiscard]] Result<std::wstring_view> widen(std::string_view utf8, std::span<wchar_t> out);

[[nodiscard]] Opened openRelative(
    HANDLE parent,
    std::wstring_view name,
    ACCESS_MASK access,
    ULONG share,
    ULONG disposition,
    ULONG options
);

[[nodiscard]] Result<DWORD> attributesOf(const OsHandle& handle);

[[nodiscard]] Result<Extractor::FileId> fileIdOf(const OsHandle& handle);

[[nodiscard]] Result<FILETIME> toFileTime(std::int64_t nanoseconds);

[[nodiscard]] Result<void>
applyTimes(const OsHandle& handle, const EntryMetadata& metadata, bool restore);

}

#endif
