#pragma once

#include "archive/reader.hpp"
#include "base/error.hpp"
#include "io/file.hpp"

#include <optional>
#include <string>
#include <vector>

namespace bale::cli {

[[nodiscard]] Result<archive::ReaderUnlock>
buildUnlock(const std::optional<std::string>& keyFile, bool promptIfNeeded);

[[nodiscard]] Result<std::array<std::byte, 32>> parseRecipientHex(std::string_view text);

[[nodiscard]] Result<std::array<std::byte, 32>> parseVerifyKey(std::string_view text);

[[nodiscard]] Result<std::vector<crypto::SecretBytes>> loadSignSeeds(const std::string& path);

}
