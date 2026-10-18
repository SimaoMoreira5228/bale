#pragma once

#include <cstdint>
#include <expected>
#include <limits>
#include <string_view>

namespace bale {

enum class ErrorKind : std::uint8_t {
    Truncated,
    Malformed,
    Unsupported,
    Integrity,
    LimitExceeded,
    UnsafePath,
    AlreadyExists,
    PasswordRequired,
    Io,
};

struct Error {
    static constexpr std::uint64_t noOffset = std::numeric_limits<std::uint64_t>::max();

    ErrorKind kind;
    std::string_view what;
    std::uint64_t offset = noOffset;
    int systemCode = 0;
};

template <typename T> using Result = std::expected<T, Error>;

[[nodiscard]] constexpr std::unexpected<Error>
fail(ErrorKind kind, std::string_view what, std::uint64_t offset = Error::noOffset) {
    return std::unexpected(
        Error{
            .kind = kind,
            .what = what,
            .offset = offset,
        }
    );
}

[[nodiscard]] constexpr std::string_view name(ErrorKind kind) {
    switch (kind) {
    case ErrorKind::Truncated:
        return "truncated";
    case ErrorKind::Malformed:
        return "malformed";
    case ErrorKind::Unsupported:
        return "unsupported";
    case ErrorKind::Integrity:
        return "integrity";
    case ErrorKind::LimitExceeded:
        return "limit exceeded";
    case ErrorKind::UnsafePath:
        return "unsafe path";
    case ErrorKind::AlreadyExists:
        return "already exists";
    case ErrorKind::PasswordRequired:
        return "password required";
    case ErrorKind::Io:
        return "i/o";
    }
    return "unknown";
}

}
