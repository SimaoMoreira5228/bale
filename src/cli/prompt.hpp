#pragma once

#include "base/error.hpp"
#include "crypto/secrets.hpp"

#include <string_view>

namespace bale::cli {

[[nodiscard]] Result<crypto::SecretBytes> promptPassword(std::string_view prompt);

}
