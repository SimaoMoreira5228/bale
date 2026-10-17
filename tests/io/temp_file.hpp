#pragma once

#include "io/file.hpp"

#include <cstddef>
#include <filesystem>
#include <random>
#include <span>
#include <string>
#include <system_error>

namespace bale::test {

class TempFile {
  public:
    explicit TempFile(std::span<const std::byte> contents) {
        std::random_device seed;
        auto name = "bale-test-" + std::to_string(seed()) + std::to_string(seed());
        path_ = std::filesystem::temp_directory_path() / name;

        auto file = File::createNew(path_);
        if (file) {
            ok_ = file->append(contents).has_value();
        }
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    ~TempFile() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    [[nodiscard]] bool ok() const {
        return ok_;
    }

    [[nodiscard]] Result<File> open() const {
        return File::openRead(path_);
    }

  private:
    std::filesystem::path path_;
    bool ok_ = false;
};

}
