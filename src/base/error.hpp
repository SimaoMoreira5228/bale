#pragma once

#include <cstdint>
#include <limits>
#include <string_view>
#include <tl/expected.hpp>

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

// NOTE: Result is tl::expected, not std::expected. Clang does not advertise
// a completed concepts implementation, which is what libstdc++ gates its
// <expected> header on, so the standard header is empty under Clang with the
// default library. The vendored replacement is CC0, single-header, and API
// compatible for everything bale uses. Do not switch back without checking
// that combination first.
template <typename T> using Result = tl::expected<T, Error>;

[[nodiscard]] constexpr tl::unexpected<Error>
fail(ErrorKind kind, std::string_view what, std::uint64_t offset = Error::noOffset) {
    return tl::unexpected<Error>(Error{
        .kind = kind,
        .what = what,
        .offset = offset,
    });
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
