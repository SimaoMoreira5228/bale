#include "security/archive_path.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>

using namespace bale;
using namespace std::string_view_literals;

namespace {

constexpr PathPolicy portable{};

constexpr PathPolicy backslashSeparator{
    .backslash = Backslash::Separator,
};

constexpr PathPolicy strict{
    .syntax = PathSyntax::Strict,
};

constexpr PathPolicy posixRaw{
    .backslash = Backslash::Literal,
    .windowsSafe = false,
    .allowRawNames = true,
};

constexpr PathPolicy posixUtf8{
    .backslash = Backslash::Literal,
    .windowsSafe = false,
};

constexpr PathPolicy windowsRaw{
    .backslash = Backslash::Literal,
    .allowRawNames = true,
};

struct Rejected {
    std::string_view input;
    const PathPolicy& policy;
    ErrorKind kind;
    std::string_view what;
};

struct Accepted {
    std::string_view input;
    const PathPolicy& policy;
    std::string_view path;
    std::uint32_t depth;
    bool directory;
};

Result<ArchivePath> normalize(
    std::string_view input,
    const PathPolicy& policy,
    std::string& out,
    const Limits& limits = Limits{}
) {
    return normalizeArchivePath(std::as_bytes(std::span(input)), policy, limits, out);
}

const std::array rejected{
    Rejected{""sv, portable, ErrorKind::UnsafePath, "empty path"},
    Rejected{"../a"sv, portable, ErrorKind::UnsafePath, "parent directory component in path"},
    Rejected{"a/../../b"sv, portable, ErrorKind::UnsafePath, "parent directory component in path"},
    Rejected{"a/.."sv, portable, ErrorKind::UnsafePath, "parent directory component in path"},
    Rejected{"./../a"sv, portable, ErrorKind::UnsafePath, "parent directory component in path"},
    Rejected{"a/b/../.."sv, posixRaw, ErrorKind::UnsafePath, "parent directory component in path"},
    Rejected{
        "a\\..\\b"sv,
        backslashSeparator,
        ErrorKind::UnsafePath,
        "parent directory component in path",
    },
    Rejected{"a\\b"sv, portable, ErrorKind::UnsafePath, "backslash in path"},
    Rejected{"..\\a"sv, portable, ErrorKind::UnsafePath, "backslash in path"},
    Rejected{"/etc/passwd"sv, portable, ErrorKind::UnsafePath, "absolute path"},
    Rejected{"/etc/passwd"sv, posixRaw, ErrorKind::UnsafePath, "absolute path"},
    Rejected{"\\x"sv, posixRaw, ErrorKind::UnsafePath, "absolute path"},
    Rejected{"//etc/passwd"sv, portable, ErrorKind::UnsafePath, "UNC or device path"},
    Rejected{"/\\x"sv, posixRaw, ErrorKind::UnsafePath, "UNC or device path"},
    Rejected{"\\\\server\\share"sv, portable, ErrorKind::UnsafePath, "UNC or device path"},
    Rejected{"\\\\?\\C:\\x"sv, backslashSeparator, ErrorKind::UnsafePath, "UNC or device path"},
    Rejected{"\\\\.\\PhysicalDrive0"sv, posixRaw, ErrorKind::UnsafePath, "UNC or device path"},
    Rejected{"C:\\x"sv, portable, ErrorKind::UnsafePath, "drive-letter prefix in path"},
    Rejected{"C:x"sv, portable, ErrorKind::UnsafePath, "drive-letter prefix in path"},
    Rejected{"z:/x"sv, posixRaw, ErrorKind::UnsafePath, "drive-letter prefix in path"},
    Rejected{"./C:t"sv, posixRaw, ErrorKind::UnsafePath, "drive-letter prefix in path"},
    Rejected{".//z:/x"sv, posixUtf8, ErrorKind::UnsafePath, "drive-letter prefix in path"},
    Rejected{"a\0b"sv, portable, ErrorKind::UnsafePath, "NUL byte in path"},
    Rejected{"a/\0"sv, posixRaw, ErrorKind::UnsafePath, "NUL byte in path"},
    Rejected{"a/\xC0\xAF"sv, portable, ErrorKind::UnsafePath, "overlong UTF-8 encoding in path"},
    Rejected{"\xC1\xBF"sv, posixUtf8, ErrorKind::UnsafePath, "overlong UTF-8 encoding in path"},
    Rejected{"\xE0\x80\xAF"sv, portable, ErrorKind::UnsafePath, "overlong UTF-8 encoding in path"},
    Rejected{
        "\xF0\x80\x80\xAF"sv,
        portable,
        ErrorKind::UnsafePath,
        "overlong UTF-8 encoding in path",
    },
    Rejected{
        "x\xED\xA0\x80\xED\xB0\x80"sv,
        portable,
        ErrorKind::UnsafePath,
        "UTF-8 encoded surrogate in path",
    },
    Rejected{
        "\xED\xBF\xBF"sv,
        windowsRaw,
        ErrorKind::UnsafePath,
        "UTF-8 encoded surrogate in path"
    },
    Rejected{"\xF4\x90\x80\x80"sv, portable, ErrorKind::UnsafePath, "invalid UTF-8 in path"},
    Rejected{"\xF5\x80\x80\x80"sv, portable, ErrorKind::UnsafePath, "invalid UTF-8 in path"},
    Rejected{"abcdefgh\x80"sv, portable, ErrorKind::UnsafePath, "invalid UTF-8 in path"},
    Rejected{"\xC3\x28"sv, portable, ErrorKind::UnsafePath, "invalid UTF-8 in path"},
    Rejected{"\xE2\x82\x28"sv, portable, ErrorKind::UnsafePath, "invalid UTF-8 in path"},
    Rejected{"\xFF\xFE"sv, posixUtf8, ErrorKind::UnsafePath, "invalid UTF-8 in path"},
    Rejected{"a\xC3"sv, portable, ErrorKind::UnsafePath, "truncated UTF-8 sequence in path"},
    Rejected{"\xF0\x9F\x98"sv, portable, ErrorKind::UnsafePath, "truncated UTF-8 sequence in path"},
    Rejected{"CON"sv, portable, ErrorKind::UnsafePath, "reserved Windows device name in path"},
    Rejected{"con.txt"sv, portable, ErrorKind::UnsafePath, "reserved Windows device name in path"},
    Rejected{"a/Nul/b"sv, portable, ErrorKind::UnsafePath, "reserved Windows device name in path"},
    Rejected{"aux .txt"sv, portable, ErrorKind::UnsafePath, "reserved Windows device name in path"},
    Rejected{
        "PRN.tar.gz"sv,
        portable,
        ErrorKind::UnsafePath,
        "reserved Windows device name in path"
    },
    Rejected{"com9"sv, portable, ErrorKind::UnsafePath, "reserved Windows device name in path"},
    Rejected{"LPT0.log"sv, portable, ErrorKind::UnsafePath, "reserved Windows device name in path"},
    Rejected{
        "COM\xC2\xB9"sv,
        portable,
        ErrorKind::UnsafePath,
        "reserved Windows device name in path",
    },
    Rejected{
        "lpt\xC2\xB3.txt"sv,
        portable,
        ErrorKind::UnsafePath,
        "reserved Windows device name in path",
    },
    Rejected{"CONOUT$"sv, portable, ErrorKind::UnsafePath, "reserved Windows device name in path"},
    Rejected{"name."sv, portable, ErrorKind::UnsafePath, "trailing dot or space in path component"},
    Rejected{
        "name /x"sv,
        portable,
        ErrorKind::UnsafePath,
        "trailing dot or space in path component"
    },
    Rejected{"..."sv, portable, ErrorKind::UnsafePath, "trailing dot or space in path component"},
    Rejected{"a<b"sv, portable, ErrorKind::UnsafePath, "character reserved on Windows in path"},
    Rejected{
        "file:stream"sv,
        portable,
        ErrorKind::UnsafePath,
        "character reserved on Windows in path"
    },
    Rejected{"a\"b|c"sv, portable, ErrorKind::UnsafePath, "character reserved on Windows in path"},
    Rejected{"what?*"sv, portable, ErrorKind::UnsafePath, "character reserved on Windows in path"},
    Rejected{"a\\b"sv, windowsRaw, ErrorKind::UnsafePath, "character reserved on Windows in path"},
    Rejected{"tab\there"sv, portable, ErrorKind::UnsafePath, "control character in path"},
    Rejected{"x/\x1F"sv, portable, ErrorKind::UnsafePath, "control character in path"},
    Rejected{"."sv, portable, ErrorKind::UnsafePath, "path names the extraction root"},
    Rejected{"./"sv, portable, ErrorKind::UnsafePath, "path names the extraction root"},
    Rejected{"././/."sv, posixRaw, ErrorKind::UnsafePath, "path names the extraction root"},
    Rejected{"./a"sv, strict, ErrorKind::UnsafePath, "dot path component"},
    Rejected{"a/./b"sv, strict, ErrorKind::UnsafePath, "dot path component"},
    Rejected{"a//b"sv, strict, ErrorKind::UnsafePath, "empty path component"},
    Rejected{"a/"sv, strict, ErrorKind::UnsafePath, "empty path component"},
};

const std::array accepted{
    Accepted{"./a/b/"sv, portable, "a/b"sv, 2, true},
    Accepted{"a//b"sv, portable, "a/b"sv, 2, false},
    Accepted{"././a/./b/."sv, portable, "a/b"sv, 2, false},
    Accepted{"a\\b"sv, backslashSeparator, "a/b"sv, 2, false},
    Accepted{"dir\\sub\\"sv, backslashSeparator, "dir/sub"sv, 2, true},
    Accepted{"console/COM10/comet.txt"sv, portable, "console/COM10/comet.txt"sv, 3, false},
    Accepted{"..a/.b/x..y"sv, portable, "..a/.b/x..y"sv, 3, false},
    Accepted{
        "caf\xC3\xA9/\xF0\x9F\x98\x80"sv,
        portable,
        "caf\xC3\xA9/\xF0\x9F\x98\x80"sv,
        2,
        false
    },
    Accepted{
        "\xEF\xBF\xBD\xF4\x8F\xBF\xBF"sv,
        portable,
        "\xEF\xBF\xBD\xF4\x8F\xBF\xBF"sv,
        1,
        false
    },
    Accepted{"a/b/c"sv, strict, "a/b/c"sv, 3, false},
    Accepted{"\xFF\xFE/CON/name./a:b"sv, posixRaw, "\xFF\xFE/CON/name./a:b"sv, 4, false},
    Accepted{"..\\a"sv, posixRaw, "..\\a"sv, 1, false},
    Accepted{"tab\there/"sv, posixUtf8, "tab\there"sv, 1, true},
};

}

TEST_CASE("normalizeArchivePath rejects hostile and non-portable paths with precise errors") {
    std::string out;
    for (const auto& entry : rejected) {
        CAPTURE(entry.input);
        auto result = normalize(entry.input, entry.policy, out);
        REQUIRE_FALSE(result);
        CHECK(result.error().kind == entry.kind);
        CHECK(result.error().what == entry.what);
        CHECK(out.empty());
    }
}

TEST_CASE("normalizeArchivePath canonicalizes tolerated spellings") {
    std::string out;
    for (const auto& entry : accepted) {
        CAPTURE(entry.input);
        auto result = normalize(entry.input, entry.policy, out);
        REQUIRE(result);
        CHECK(result->path == entry.path);
        CHECK(result->depth == entry.depth);
        CHECK(result->directory == entry.directory);
    }
}

TEST_CASE("normalizeArchivePath enforces length, depth and component limits at the boundary") {
    const Limits limits{
        .maxPathBytes = 24,
        .maxDepth = 3,
    };
    const PathPolicy shortNames{
        .maxComponentBytes = 8,
    };
    std::string out;

    CHECK(normalize("abcdefgh/abcdefgh/abcdef"sv, shortNames, out, limits));
    auto tooLong = normalize("abcdefgh/abcdefgh/abcdefg"sv, shortNames, out, limits);
    REQUIRE_FALSE(tooLong);
    CHECK(tooLong.error().kind == ErrorKind::LimitExceeded);
    CHECK(tooLong.error().what == "path exceeds maximum length");

    auto component = normalize("abcdefghi"sv, shortNames, out, limits);
    REQUIRE_FALSE(component);
    CHECK(component.error().kind == ErrorKind::UnsafePath);
    CHECK(component.error().what == "path component too long");

    auto dotted = normalize("./a/./b/./c/"sv, shortNames, out, limits);
    REQUIRE(dotted);
    CHECK(dotted->depth == 3);

    auto deep = normalize("a/b/c/d"sv, shortNames, out, limits);
    REQUIRE_FALSE(deep);
    CHECK(deep.error().kind == ErrorKind::LimitExceeded);
    CHECK(deep.error().what == "path exceeds maximum depth");

    std::string longest(255, 'x');
    CHECK(normalize(longest, portable, out));
    longest.push_back('x');
    CHECK(normalize(longest, portable, out).error().what == "path component too long");

    std::string nested;
    for (int i = 0; i < 257; ++i) {
        nested += "d/";
    }
    CHECK(normalize(nested, portable, out).error().what == "path exceeds maximum depth");
    nested.resize(std::size_t{256} * 2);
    CHECK(normalize(nested, portable, out)->depth == 256);
}

TEST_CASE("normalizeArchivePath reuses the caller buffer without reallocating") {
    std::string out;
    out.reserve(64);
    const char* storage = out.data();

    auto first = normalize("./one/two/three"sv, portable, out);
    REQUIRE(first);
    CHECK(first->path.data() == storage);

    CHECK_FALSE(normalize("../escape"sv, portable, out));

    auto second = normalize("four//five/"sv, portable, out);
    REQUIRE(second);
    CHECK(second->path == "four/five");
    CHECK(out.data() == storage);
}
