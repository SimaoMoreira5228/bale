#pragma once

#include "base/error.hpp"
#include "formats/wim/header.hpp"
#include "io/file.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace bale::wim {

struct ImageInfo {
    std::string name;
};

[[nodiscard]] Result<std::vector<ImageInfo>>
parseImageList(const File& file, const Header& header, const Limits& limits);

}
