#pragma once

#include <string>
#include <string_view>

namespace bale::cli {

[[nodiscard]] std::string_view escapeForTerminal(std::string_view raw, std::string& buffer);

}
