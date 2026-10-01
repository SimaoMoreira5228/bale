#include "io/file.hpp"

#include "base/checked.hpp"

#include <algorithm>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
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

File::File(File&& other) noexcept : handle_(std::exchange(other.handle_, invalidHandle)) {
}

File& File::operator=(File&& other) noexcept {
    if (this != &other) {
        close();
        handle_ = std::exchange(other.handle_, invalidHandle);
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
        FILE_SHARE_READ,
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

Result<File> File::createNew(const std::filesystem::path& path) {
    HANDLE handle = CreateFileW(
        path.c_str(),
        GENERIC_READ | FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (handle == INVALID_HANDLE_VALUE) {
        return systemFailure("cannot create file");
    }
    return File(handle);
}

void File::close() {
    if (handle_ != invalidHandle) {
        CloseHandle(handle_);
        handle_ = invalidHandle;
    }
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

Result<File> File::createNew(const std::filesystem::path& path) {
    int fd = -1;
    do {
        fd = ::open(path.c_str(), O_RDWR | O_APPEND | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0) {
        return systemFailure("cannot create file");
    }
    return File(fd);
}

void File::close() {
    if (handle_ != invalidHandle) {
        ::close(handle_);
        handle_ = invalidHandle;
    }
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
