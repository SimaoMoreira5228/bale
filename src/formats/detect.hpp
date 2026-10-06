#pragma once

#include "base/error.hpp"
#include "formats/compressed/stream.hpp"
#include "io/file.hpp"

#include <cstdint>
#include <string_view>

namespace bale {

enum class Container : std::uint8_t {
    Unknown,
    Bale,
    Zip,
    Tar,
    SingleFile,
};

// NOTE: a compression layer wraps a container; SingleFile is a compressed stream whose content
// is not a recognized archive and is treated as one file.
struct ArchiveFormat {
    Container container = Container::Unknown;
    Compression compression = Compression::None;

    friend bool operator==(const ArchiveFormat&, const ArchiveFormat&) = default;
};

[[nodiscard]] std::string_view name(ArchiveFormat format);

[[nodiscard]] Result<ArchiveFormat> detectFormat(const File& file);

}
