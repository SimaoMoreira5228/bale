#include "archive/manifest.hpp"
#include "fuzz/memory_file.hpp"
#include "security/archive_path.hpp"
#include "security/case_fold.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace {

constexpr std::size_t maxPaths = 64;

void require(bool condition) {
    if (!condition) {
        __builtin_trap();
    }
}

bale::PathPolicy policyFor(std::uint8_t selector) {
    bale::PathPolicy policy;
    policy.backslash = static_cast<bale::Backslash>(selector % 3);
    policy.syntax = (selector & 0x04) != 0 ? bale::PathSyntax::Strict : bale::PathSyntax::Lenient;
    policy.windowsSafe = (selector & 0x08) != 0;
    policy.allowRawNames = (selector & 0x10) != 0;
    policy.maxComponentBytes = (selector & 0x20) != 0 ? 16 : 255;
    return policy;
}

std::string asciiCaseSwapped(std::string_view text) {
    std::string swapped(text);
    for (char& c : swapped) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        } else if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return swapped;
}

void checkPath(
    std::string_view raw,
    const bale::PathPolicy& policy,
    bale::CaseFoldSet& folds,
    std::uint64_t id
) {
    bale::Limits limits;
    limits.maxPathBytes = 1024;
    limits.maxDepth = 16;

    std::string normalized;
    auto result =
        bale::normalizeArchivePath(std::as_bytes(std::span(raw)), policy, limits, normalized);
    std::string scratch;
    static_cast<void>(bale::archive::validateEntryPath(raw, limits, scratch));
    if (!result) {
        return;
    }

    require(!result->path.empty() && result->path.size() <= raw.size());
    require(result->depth >= 1 && result->depth <= limits.maxDepth);
    require(result->path.front() != '/' && result->path.back() != '/');

    std::string again;
    auto renormalized =
        bale::normalizeArchivePath(std::as_bytes(std::span(result->path)), policy, limits, again);
    require(renormalized.has_value() && renormalized->path == result->path);

    std::string stable(result->path);
    auto inserted = folds.insertOrFindCollision(stable, id);
    if (!inserted) {
        require(folds.insertOrFindCollision(stable, id + 1) == id);
        require(folds.insertOrFindCollision(asciiCaseSwapped(stable), id + 1) == id);
    }
}

}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }

    auto policy = policyFor(data[0]);
    std::string_view text(reinterpret_cast<const char*>(data + 1), size - 1);
    bale::CaseFoldSet folds;
    std::uint64_t id = 0;
    while (id < maxPaths * 2) {
        auto newline = text.find('\n');
        checkPath(text.substr(0, newline), policy, folds, id);
        id += 2;
        if (newline == std::string_view::npos) {
            break;
        }
        text.remove_prefix(newline + 1);
    }
    return 0;
}
