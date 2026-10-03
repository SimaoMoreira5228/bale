#pragma once

#include "base/error.hpp"
#include "io/file.hpp"

#include <cstdint>
#include <string_view>

namespace bale {

enum class ArchiveFormat : std::uint8_t {
    Unknown,
    Bale,
    Zip,
    Tar,
};

[[nodiscard]] std::string_view name(ArchiveFormat format);

[[nodiscard]] Result<ArchiveFormat> detectFormat(const File& file);

}
