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

    [[nodiscard]] static Result<File> openRegularNoFollow(const std::filesystem::path& path);

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
    [[nodiscard]] Result<void> writeAt(std::uint64_t offset, std::span<const std::byte> data);
    [[nodiscard]] Result<void> truncate(std::uint64_t size);
    [[nodiscard]] Result<void> sync();

  private:
#ifdef _WIN32
    using Handle = void*;
#else
    using Handle = int;
#endif

    explicit File(Handle handle, bool appendOnly = false) :
        handle_(handle), appendOnly_(appendOnly) {
    }

    void close();

    Handle handle_;
    bool appendOnly_ = false;
};

}
