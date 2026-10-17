#pragma once

#include "base/error.hpp"
#include "security/budget.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace bale {

enum class Backslash : std::uint8_t {
    Reject,
    Separator,
    Literal,
};

enum class PathSyntax : std::uint8_t {
    Lenient,
    Strict,
};

struct PathPolicy {
    Backslash backslash = Backslash::Reject;
    PathSyntax syntax = PathSyntax::Lenient;
    // NOTE: Windows-safe names imply UTF-8 validation, whatever allowRawNames says.
    bool windowsSafe = true;
    bool allowRawNames = false;
    std::uint32_t maxComponentBytes = 255;
};

struct ArchivePath {
    std::string_view path;
    std::uint32_t depth = 0;
    bool directory = false;
};

// NOTE: the returned view points into `out`, which is reused across calls to avoid allocations.
[[nodiscard]] Result<ArchivePath> normalizeArchivePath(
    std::span<const std::byte> raw,
    const PathPolicy& policy,
    const Limits& limits,
    std::string& out
);

}
