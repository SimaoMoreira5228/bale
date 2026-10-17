#pragma once

#include "base/error.hpp"

#include <cstdint>

#include <string_view>

namespace bale::cli {

enum class ExitCode : std::uint8_t {
    Ok = 0,
    Usage = 2,
    Unsupported = 3,
    InvalidArchive = 4,
    Integrity = 5,
    PasswordRequired = 6,
    UnsafePath = 7,
    Io = 8,
    LimitExceeded = 9,
};

[[nodiscard]] ExitCode exitCodeFor(ErrorKind kind);

void reportError(std::string_view context, const Error& error);

struct ListOptions {
    bool detailed = false;
};

[[nodiscard]] ExitCode listArchive(std::string_view argument, const ListOptions& options);

[[nodiscard]] ExitCode testArchive(std::string_view argument);

}
