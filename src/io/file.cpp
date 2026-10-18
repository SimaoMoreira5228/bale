#include "io/file.hpp"

#include "base/checked.hpp"

#include <algorithm>
#include <limits>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace bale {

namespace {

#ifdef _WIN32
const HANDLE invalidHandle = INVALID_HANDLE_VALUE;
#else
constexpr int invalidHandle = -1;
#endif

std::unexpected<Error>
systemFailure(std::string_view what, std::uint64_t offset = Error::noOffset) {
    auto failure = fail(ErrorKind::Io, what, offset);
#ifdef _WIN32
    failure.error().systemCode = static_cast<int>(GetLastError());
#else
    failure.error().systemCode = errno;
#endif
    return failure;
}

}

File::File(File&& other) noexcept :
    handle_(std::exchange(other.handle_, invalidHandle)), appendOnly_(other.appendOnly_) {
}

File& File::operator=(File&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, invalidHandle);
        appendOnly_ = other.appendOnly_;
    }
    return *this;
}

File::~File() {
    close();
}

Result<void> File::readExactAt(std::uint64_t offset, std::span<std::byte> out) const {
    while (!out.empty()) {
        auto count = readAt(offset, out);
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            return fail(ErrorKind::Truncated, "file ended before requested range", offset);
        }

        out = out.subspan(*count);
        offset += *count;
    }
    return {};
}

#ifdef _WIN32

Result<File> File::openRead(const std::filesystem::path& path) {
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return systemFailure("cannot open file for reading");
    }
    return File(handle);
}

Result<File> File::openAppend(const std::filesystem::path& path) {
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_READ | FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return systemFailure("cannot open file for appending");
    }
    File file(handle, true);

    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(handle, &information)) {
        return systemFailure("cannot query file information");
    }
    constexpr DWORD notRegular = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
    if ((information.dwFileAttributes & notRegular) != 0 || GetFileType(handle) != FILE_TYPE_DISK) {
        return fail(ErrorKind::Unsupported, "not a regular file");
    }
    return file;
}

Result<File> File::openRegularNoFollow(const std::filesystem::path& path) {
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return systemFailure("cannot open file for reading");
    }
    File file(handle);

    BY_HANDLE_FILE_INFORMATION information{};
    if (!GetFileInformationByHandle(handle, &information)) {
        return systemFailure("cannot query file information");
    }
    constexpr DWORD notRegular = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
    if ((information.dwFileAttributes & notRegular) != 0 || GetFileType(handle) != FILE_TYPE_DISK) {
        return fail(ErrorKind::Unsupported, "not a regular file");
    }
    return file;
}

Result<File> File::createNew(const std::filesystem::path& path) {
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        auto failure = systemFailure("cannot create file");
        if (failure.error().systemCode == ERROR_FILE_EXISTS) {
            failure.error().kind = ErrorKind::AlreadyExists;
        }
        return failure;
    }
    return File(handle);
}

void File::close() {
    if (handle_ != invalidHandle) {
        CloseHandle(handle_);
        handle_ = invalidHandle;
    }
}

Result<File> File::duplicate() const {
    HANDLE process = GetCurrentProcess();
    HANDLE copy = INVALID_HANDLE_VALUE;
    if (!DuplicateHandle(process, handle_, process, &copy, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        return systemFailure("cannot duplicate file handle");
    }
    return File(copy, appendOnly_);
}

Result<std::uint64_t> File::size() const {
    LARGE_INTEGER size;
    if (!GetFileSizeEx(handle_, &size)) {
        return systemFailure("cannot query file size");
    }
    return static_cast<std::uint64_t>(size.QuadPart);
}

Result<std::size_t> File::readAt(std::uint64_t offset, std::span<std::byte> out) const {
    OVERLAPPED position{};
    position.Offset = static_cast<DWORD>(offset);
    position.OffsetHigh = static_cast<DWORD>(offset >> 32);

    auto request = static_cast<DWORD>(std::min<std::size_t>(out.size(), MAXDWORD));
    DWORD count = 0;
    if (!ReadFile(handle_, out.data(), request, &count, &position)) {
        if (GetLastError() == ERROR_HANDLE_EOF) {
            return 0;
        }
        return systemFailure("read failed", offset);
    }
    return count;
}

Result<void> File::append(std::span<const std::byte> data) {
    while (!data.empty()) {
        auto request = static_cast<DWORD>(std::min<std::size_t>(data.size(), MAXDWORD));
        DWORD count = 0;
        if (!WriteFile(handle_, data.data(), request, &count, nullptr)) {
            return systemFailure("write failed");
        }

        data = data.subspan(count);
    }
    return {};
}

Result<void> File::writeAt(std::uint64_t offset, std::span<const std::byte> data) {
    if (appendOnly_) {
        return fail(ErrorKind::Unsupported, "file is open for appending only");
    }

    auto position = offset;
    while (!data.empty()) {
        OVERLAPPED overlapped{};
        overlapped.Offset = static_cast<DWORD>(position);
        overlapped.OffsetHigh = static_cast<DWORD>(position >> 32);

        auto request = static_cast<DWORD>(std::min<std::size_t>(data.size(), MAXDWORD));
        DWORD count = 0;
        if (!WriteFile(handle_, data.data(), request, &count, &overlapped)) {
            return systemFailure("write failed", position);
        }

        data = data.subspan(count);
        position += count;
    }

    LARGE_INTEGER zero{};
    if (!SetFilePointerEx(handle_, zero, nullptr, FILE_END)) {
        return systemFailure("cannot seek to the end of the file");
    }
    return {};
}

Result<void> File::truncate(std::uint64_t size) {
    if (size > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max())) {
        return fail(ErrorKind::Io, "file size exceeds platform limit", size);
    }
    LARGE_INTEGER position{};
    position.QuadPart = static_cast<LONGLONG>(size);
    if (!SetFilePointerEx(handle_, position, nullptr, FILE_BEGIN) || !SetEndOfFile(handle_)) {
        return systemFailure("cannot truncate file", size);
    }
    return {};
}

Result<void> File::sync() {
    if (!FlushFileBuffers(handle_)) {
        return systemFailure("flush failed");
    }
    return {};
}

#else

Result<File> File::openRead(const std::filesystem::path& path) {
    int fd = -1;
    do {
        fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        return systemFailure("cannot open file for reading");
    }
    return File(fd);
}

Result<File> File::openAppend(const std::filesystem::path& path) {
    int fd = -1;
    do {
        fd = ::open(path.c_str(), O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        return systemFailure("cannot open file for appending");
    }
    File file(fd, true);

    struct stat status{};
    if (::fstat(fd, &status) != 0) {
        return systemFailure("cannot query file status");
    }
    if (!S_ISREG(status.st_mode)) {
        return fail(ErrorKind::Unsupported, "not a regular file");
    }
    return file;
}

Result<File> File::openRegularNoFollow(const std::filesystem::path& path) {
    int fd = -1;
    do {
        fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        return systemFailure("cannot open file for reading");
    }
    File file(fd);

    struct stat status{};
    if (::fstat(fd, &status) != 0) {
        return systemFailure("cannot query file status");
    }
    if (!S_ISREG(status.st_mode)) {
        return fail(ErrorKind::Unsupported, "not a regular file");
    }
    return file;
}

Result<File> File::createNew(const std::filesystem::path& path) {
    int fd = -1;
    do {
        fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        auto failure = systemFailure("cannot create file");
        if (failure.error().systemCode == EEXIST) {
            failure.error().kind = ErrorKind::AlreadyExists;
        }
        return failure;
    }
    return File(fd);
}

void File::close() {
    if (handle_ != invalidHandle) {
        ::close(handle_);
        handle_ = invalidHandle;
    }
}

Result<File> File::duplicate() const {
    int fd = ::fcntl(handle_, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) {
        return systemFailure("cannot duplicate file handle");
    }
    return File(fd, appendOnly_);
}

Result<std::uint64_t> File::size() const {
    struct stat status{};
    if (::fstat(handle_, &status) != 0) {
        return systemFailure("cannot query file size");
    }
    return static_cast<std::uint64_t>(status.st_size);
}

Result<std::size_t> File::readAt(std::uint64_t offset, std::span<std::byte> out) const {
    auto position = checkedCast<off_t>(offset);
    if (!position) {
        return fail(ErrorKind::Io, "read offset exceeds platform limit", offset);
    }

    ssize_t count = -1;
    do {
        count = ::pread(handle_, out.data(), out.size(), *position);
    } while (count < 0 && errno == EINTR);

    if (count < 0) {
        return systemFailure("read failed", offset);
    }
    return static_cast<std::size_t>(count);
}

Result<void> File::append(std::span<const std::byte> data) {
    while (!data.empty()) {
        ssize_t count = ::write(handle_, data.data(), data.size());
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            return systemFailure("write failed");
        }

        data = data.subspan(static_cast<std::size_t>(count));
    }
    return {};
}

Result<void> File::writeAt(std::uint64_t offset, std::span<const std::byte> data) {
    if (appendOnly_) {
        return fail(ErrorKind::Unsupported, "file is open for appending only");
    }

    auto position = offset;
    while (!data.empty()) {
        auto start = checkedCast<off_t>(position);
        if (!start) {
            return fail(ErrorKind::Io, "write offset exceeds platform limit", position);
        }

        ssize_t count = ::pwrite(handle_, data.data(), data.size(), *start);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            return systemFailure("write failed", position);
        }

        data = data.subspan(static_cast<std::size_t>(count));
        position += static_cast<std::uint64_t>(count);
    }
    return {};
}

Result<void> File::truncate(std::uint64_t size) {
    auto length = checkedCast<off_t>(size);
    if (!length) {
        return fail(ErrorKind::Io, "file size exceeds platform limit", size);
    }
    if (::ftruncate(handle_, *length) != 0) {
        return systemFailure("cannot truncate file", size);
    }
    if (::lseek(handle_, *length, SEEK_SET) < 0) {
        return systemFailure("cannot seek after truncating", size);
    }
    return {};
}

Result<void> File::sync() {
#ifdef __APPLE__
    // NOTE: plain fsync on macOS does not force the drive cache; F_FULLFSYNC does.
    if (::fcntl(handle_, F_FULLFSYNC) == 0) {
        return {};
    }
#endif
    if (::fsync(handle_) != 0) {
        return systemFailure("fsync failed");
    }
    return {};
}

#endif

}
