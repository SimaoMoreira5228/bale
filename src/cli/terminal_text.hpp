#pragma once

#include <string>
#include <string_view>

namespace bale::cli {

// SECURITY: archive names are untrusted; control characters, invalid UTF-8 and bidi overrides
// are escaped so a listing cannot drive the terminal or visually reorder names.
[[nodiscard]] std::string_view escapeForTerminal(std::string_view raw, std::string& buffer);

}
