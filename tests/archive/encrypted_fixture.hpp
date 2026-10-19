#pragma once

#include "archive/writer.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::test {

inline crypto::KdfParams testKdf() {
    return {.opslimit = 1, .memlimitBytes = 8192};
}

inline archive::WriterSecrets testWriterSecrets() {
    archive::WriterSecrets secrets;
    secrets.hasPassword = true;
    auto made = crypto::SecretBytes::make(7);
    REQUIRE(made);
    secrets.password = std::move(*made);
    std::string_view pw = "test-pw";
    std::ranges::copy(std::as_bytes(std::span(pw)), secrets.password.mut().begin());
    secrets.kdf = testKdf();
    return secrets;
}

inline archive::ReaderUnlock testUnlock() {
    archive::ReaderUnlock unlock;
    unlock.hasPassword = true;
    auto made = crypto::SecretBytes::make(7);
    REQUIRE(made);
    unlock.password = std::move(*made);
    std::string_view pw = "test-pw";
    std::ranges::copy(std::as_bytes(std::span(pw)), unlock.password.mut().begin());
    return unlock;
}

inline std::filesystem::path tempArchive(const std::string& name) {
    auto path = std::filesystem::temp_directory_path() / name;
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return path;
}

}
