#pragma once

#include "base/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>

namespace bale {

class File {
  public:
    [[nodiscard]] static Result<File> openRead(const std::filesystem::path& path);
    [[nodiscard]] static Result<File> openAppend(const std::filesystem::path& path);

    // SECURITY: refuses symlinks, reparse points and anything else that is not a regular file, so
    // a path swapped for a link after it was inspected is never followed.
    [[nodiscard]] static Result<File> openRegularNoFollow(const std::filesystem::path& path);

    // SECURITY: fails if the path already exists, so a planted file or symlink is never reused.
    [[nodiscard]] static Result<File> createNew(const std::filesystem::path& path);

    File(const File&) = delete;
    File& operator=(const File&) = delete;
    File(File&& other) noexcept;
    File& operator=(File&& other) noexcept;
    ~File();

    [[nodiscard]] Result<File> duplicate() const;

    [[nodiscard]] Result<std::uint64_t> size() const;

    [[nodiscard]] Result<std::size_t> readAt(std::uint64_t offset, std::span<std::byte> out) const;
    [[nodiscard]] Result<void> readExactAt(std::uint64_t offset, std::span<std::byte> out) const;

    [[nodiscard]] Result<void> append(std::span<const std::byte> data);
    [[nodiscard]] Result<void> truncate(std::uint64_t size);
    [[nodiscard]] Result<void> sync();

  private:
#ifdef _WIN32
    using Handle = void*;
#else
    using Handle = int;
#endif

    explicit File(Handle handle) : handle_(handle) {
    }

    void close();

    Handle handle_;
};

}
