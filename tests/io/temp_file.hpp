#pragma once

#include "io/file.hpp"

#include <cstddef>
#include <filesystem>
#include <random>
#include <span>
#include <string>
#include <system_error>

namespace bale::test {

class TempPath {
  public:
    TempPath() {
        std::random_device seed;
        auto name = "bale-test-" + std::to_string(seed()) + std::to_string(seed());
        path_ = std::filesystem::temp_directory_path() / name;
    }

    TempPath(const TempPath&) = delete;
    TempPath& operator=(const TempPath&) = delete;

    ~TempPath() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    [[nodiscard]] const std::filesystem::path& path() const {
        return path_;
    }

  private:
    std::filesystem::path path_;
};

class TempFile {
  public:
    explicit TempFile(std::span<const std::byte> contents) {
        auto file = File::createNew(path_.path());
        if (file) {
            ok_ = file->append(contents).has_value();
        }
    }

    [[nodiscard]] bool ok() const {
        return ok_;
    }

    [[nodiscard]] const std::filesystem::path& path() const {
        return path_.path();
    }

    [[nodiscard]] Result<File> open() const {
        return File::openRead(path_.path());
    }

  private:
    TempPath path_;
    bool ok_ = false;
};

}
