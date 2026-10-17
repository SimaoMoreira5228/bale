#include "security/archive_path.hpp"

#include "base/endian.hpp"

#include <array>

namespace bale {

namespace {

constexpr std::array<bool, 256> windowsForbidden = [] {
    std::array<bool, 256> table{};
    for (std::size_t i = 0; i < 0x20; ++i) {
        table[i] = true;
    }
    for (char c : std::string_view("<>:\"|?*\\")) {
        table[static_cast<unsigned char>(c)] = true;
    }
    return table;
}();

[[nodiscard]] constexpr bool isSlashLike(char c) {
    return c == '/' || c == '\\';
}

[[nodiscard]] constexpr bool isAsciiAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

[[nodiscard]] constexpr bool isContinuation(unsigned char byte) {
    return (byte & 0xC0) == 0x80;
}

[[nodiscard]] constexpr char asciiUpper(char c) {
    if (c >= 'a' && c <= 'z') {
        return static_cast<char>(c - ('a' - 'A'));
    }
    return c;
}

[[nodiscard]] constexpr bool
equalsIgnoringAsciiCase(std::string_view text, std::string_view upper) {
    if (text.size() != upper.size()) {
        return false;
    }

    for (std::size_t i = 0; i < text.size(); ++i) {
        if (asciiUpper(text[i]) != upper[i]) {
            return false;
        }
    }
    return true;
}

Result<void> checkUtf8(std::string_view text) {
    const auto* bytes = reinterpret_cast<const std::byte*>(text.data());
    const std::size_t size = text.size();
    std::size_t i = 0;

    while (i < size) {
        while (size - i >= 8 && (loadLe<std::uint64_t>(bytes + i) & 0x8080808080808080) == 0) {
            i += 8;
        }
        if (i == size) {
            break;
        }

        auto lead = static_cast<unsigned char>(text[i]);
        if (lead < 0x80) {
            ++i;
            continue;
        }

        std::size_t length = 0;
        unsigned char low = 0x80;
        unsigned char high = 0xBF;
        if (lead == 0xC0 || lead == 0xC1) {
            return fail(ErrorKind::UnsafePath, "overlong UTF-8 encoding in path");
        }
        if (lead < 0xC2) {
            return fail(ErrorKind::UnsafePath, "invalid UTF-8 in path");
        }
        if (lead < 0xE0) {
            length = 2;
        } else if (lead < 0xF0) {
            length = 3;
            low = lead == 0xE0 ? 0xA0 : 0x80;
            high = lead == 0xED ? 0x9F : 0xBF;
        } else if (lead < 0xF5) {
            length = 4;
            low = lead == 0xF0 ? 0x90 : 0x80;
            high = lead == 0xF4 ? 0x8F : 0xBF;
        } else {
            return fail(ErrorKind::UnsafePath, "invalid UTF-8 in path");
        }

        if (length > size - i) {
            return fail(ErrorKind::UnsafePath, "truncated UTF-8 sequence in path");
        }

        auto second = static_cast<unsigned char>(text[i + 1]);
        if (second < low || second > high) {
            if (isContinuation(second) && (lead == 0xE0 || lead == 0xF0)) {
                return fail(ErrorKind::UnsafePath, "overlong UTF-8 encoding in path");
            }
            if (isContinuation(second) && lead == 0xED) {
                return fail(ErrorKind::UnsafePath, "UTF-8 encoded surrogate in path");
            }
            return fail(ErrorKind::UnsafePath, "invalid UTF-8 in path");
        }

        for (std::size_t k = 2; k < length; ++k) {
            if (!isContinuation(static_cast<unsigned char>(text[i + k]))) {
                return fail(ErrorKind::UnsafePath, "invalid UTF-8 in path");
            }
        }
        i += length;
    }
    return {};
}

[[nodiscard]] bool isReservedDeviceName(std::string_view component) {
    auto stem = component.substr(0, component.find('.'));
    while (!stem.empty() && stem.back() == ' ') {
        stem.remove_suffix(1);
    }

    if (stem.size() == 3) {
        return equalsIgnoringAsciiCase(stem, "CON") || equalsIgnoringAsciiCase(stem, "PRN") ||
            equalsIgnoringAsciiCase(stem, "AUX") || equalsIgnoringAsciiCase(stem, "NUL");
    }
    if (stem.size() < 4) {
        return false;
    }

    auto head = stem.substr(0, 3);
    if (!equalsIgnoringAsciiCase(head, "COM") && !equalsIgnoringAsciiCase(head, "LPT")) {
        return equalsIgnoringAsciiCase(stem, "CONIN$") || equalsIgnoringAsciiCase(stem, "CONOUT$");
    }

    auto suffix = stem.substr(3);
    if (suffix.size() == 1) {
        return suffix[0] >= '0' && suffix[0] <= '9';
    }
    return suffix == "\xC2\xB9" || suffix == "\xC2\xB2" || suffix == "\xC2\xB3";
}

Result<void> checkWindowsName(std::string_view component) {
    for (char c : component) {
        auto byte = static_cast<unsigned char>(c);
        if (!windowsForbidden[byte]) {
            continue;
        }
        if (byte < 0x20) {
            return fail(ErrorKind::UnsafePath, "control character in path");
        }
        return fail(ErrorKind::UnsafePath, "character reserved on Windows in path");
    }

    if (component.back() == '.' || component.back() == ' ') {
        return fail(ErrorKind::UnsafePath, "trailing dot or space in path component");
    }

    if (isReservedDeviceName(component)) {
        return fail(ErrorKind::UnsafePath, "reserved Windows device name in path");
    }
    return {};
}

[[nodiscard]] constexpr bool hasDrivePrefix(std::string_view text) {
    return text.size() >= 2 && isAsciiAlpha(text[0]) && text[1] == ':';
}

Result<void> checkPrefix(std::string_view text) {
    if (isSlashLike(text[0])) {
        if (text.size() > 1 && isSlashLike(text[1])) {
            return fail(ErrorKind::UnsafePath, "UNC or device path");
        }
        return fail(ErrorKind::UnsafePath, "absolute path");
    }

    if (hasDrivePrefix(text)) {
        return fail(ErrorKind::UnsafePath, "drive-letter prefix in path");
    }
    return {};
}

Result<void> appendComponent(
    std::string_view component,
    const PathPolicy& policy,
    const Limits& limits,
    std::string& out,
    std::uint32_t& depth
) {
    const bool strict = policy.syntax == PathSyntax::Strict;
    if (component.empty()) {
        if (strict) {
            return fail(ErrorKind::UnsafePath, "empty path component");
        }
        return {};
    }

    if (component == ".") {
        if (strict) {
            return fail(ErrorKind::UnsafePath, "dot path component");
        }
        return {};
    }

    if (component == "..") {
        return fail(ErrorKind::UnsafePath, "parent directory component in path");
    }

    if (component.size() > policy.maxComponentBytes) {
        return fail(ErrorKind::UnsafePath, "path component too long");
    }

    if (policy.windowsSafe) {
        auto checked = checkWindowsName(component);
        if (!checked) {
            return checked;
        }
    }

    if (out.empty() && hasDrivePrefix(component)) {
        return fail(ErrorKind::UnsafePath, "drive-letter prefix in path");
    }

    if (depth >= limits.maxDepth) {
        return fail(ErrorKind::LimitExceeded, "path exceeds maximum depth");
    }

    ++depth;
    if (!out.empty()) {
        out.push_back('/');
    }
    out.append(component);
    return {};
}

}

Result<ArchivePath> normalizeArchivePath(
    std::span<const std::byte> raw,
    const PathPolicy& policy,
    const Limits& limits,
    std::string& out
) {
    out.clear();
    if (raw.empty()) {
        return fail(ErrorKind::UnsafePath, "empty path");
    }
    if (raw.size() > limits.maxPathBytes) {
        return fail(ErrorKind::LimitExceeded, "path exceeds maximum length");
    }

    std::string_view text(reinterpret_cast<const char*>(raw.data()), raw.size());
    if (text.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "NUL byte in path");
    }

    auto prefix = checkPrefix(text);
    if (!prefix) {
        return std::unexpected(prefix.error());
    }

    if (policy.backslash == Backslash::Reject && text.find('\\') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "backslash in path");
    }

    if (policy.windowsSafe || !policy.allowRawNames) {
        auto utf8 = checkUtf8(text);
        if (!utf8) {
            return std::unexpected(utf8.error());
        }
    }

    const bool backslashSeparates = policy.backslash == Backslash::Separator;
    auto isSeparator = [backslashSeparates](char c) {
        return c == '/' || (backslashSeparates && c == '\\');
    };

    ArchivePath result;
    result.directory = isSeparator(text.back());

    out.reserve(text.size());
    std::size_t start = 0;
    while (start <= text.size()) {
        std::size_t end = start;
        while (end < text.size() && !isSeparator(text[end])) {
            ++end;
        }

        auto appended =
            appendComponent(text.substr(start, end - start), policy, limits, out, result.depth);
        if (!appended) {
            out.clear();
            return std::unexpected(appended.error());
        }
        start = end + 1;
    }

    if (out.empty()) {
        return fail(ErrorKind::UnsafePath, "path names the extraction root");
    }

    result.path = out;
    return result;
}

}
