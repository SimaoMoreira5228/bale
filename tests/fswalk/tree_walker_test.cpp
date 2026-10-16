#include "fswalk/tree_walker.hpp"

#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

using namespace bale;

namespace fs = std::filesystem;

namespace {

struct Walked {
    std::string path;
    std::string target;
    std::uint64_t size = 0;
    WalkKind kind = WalkKind::Regular;
};

std::vector<Walked> walkAll(TreeWalker& walker) {
    std::vector<Walked> walked;
    while (true) {
        auto next = walker.next();
        REQUIRE(next);
        if (*next == nullptr) {
            return walked;
        }

        const WalkEntry& entry = **next;
        CHECK((entry.file != nullptr) == (entry.kind == WalkKind::Regular));
        walked.push_back(
            Walked{
                .path = std::string(entry.path),
                .target = std::string(entry.target),
                .size = entry.size,
                .kind = entry.kind,
            }
        );
    }
}

}

#ifdef _WIN32

TEST_CASE("a Windows name that is not valid UTF-16 is skipped with a reason") {
    bale::test::TempPath temp;
    const fs::path root = temp.path() / "tree";
    fs::create_directories(root / "dir");
    std::ofstream(root / "dir" / L"bad\xD800name", std::ios::binary) << "x";
    std::ofstream(root / "dir" / L"café", std::ios::binary) << "y";
    if (!fs::exists(root / "dir" / L"bad\xD800name")) {
        MESSAGE("the filesystem cannot store unpaired surrogates");
        return;
    }

    auto walker = TreeWalker::open(root);
    REQUIRE(walker);
    auto walked = walkAll(*walker);
    REQUIRE(walked.size() == 2);
    CHECK(walked[1].path == "dir/caf\xC3\xA9");
    REQUIRE(walker->skipped().size() == 1);
    CHECK(walker->skipped()[0].path == "dir/bad\xEF\xBF\xBDname");
    CHECK(walker->skipped()[0].reason == "name is not valid UTF-16");
}

#else

TEST_CASE("TreeWalker visits a sorted tree without following links and skips special files") {
    bale::test::TempPath temp;
    const fs::path root = temp.path() / "tree";
    fs::create_directories(root / "b" / "empty");
    std::ofstream(root / "a.txt", std::ios::binary) << "hello";
    std::ofstream(root / "b" / "c.txt", std::ios::binary) << "";
    std::ofstream(root / "self.bale", std::ios::binary) << "archive";
    fs::create_hard_link(root / "a.txt", root / "h");
    fs::create_directory_symlink(root / "b", root / "link");
    REQUIRE(::mkfifo((root / "fifo").c_str(), 0600) == 0);

    WalkOptions options;
    options.exclude = root / "self.bale";
    auto walker = TreeWalker::open(root, options);
    REQUIRE(walker);
    auto walked = walkAll(*walker);

    REQUIRE(walked.size() == 6);
    CHECK(walked[0].path == "a.txt");
    CHECK(walked[0].size == 5);
    CHECK(walked[1].path == "b");
    CHECK(walked[1].kind == WalkKind::Directory);
    CHECK(walked[2].path == "b/c.txt");
    CHECK(walked[3].path == "b/empty");
    CHECK(walked[4].path == "h");
    CHECK(walked[4].kind == WalkKind::HardLink);
    CHECK(walked[4].target == "a.txt");
    CHECK(walked[5].path == "link");
    CHECK(walked[5].kind == WalkKind::Symlink);

    REQUIRE(walker->skipped().size() == 2);
    CHECK(walker->skipped()[0].path == "fifo");
    CHECK(walker->skipped()[1].reason == "the archive being written");

    options.hardLinks = false;
    auto copies = TreeWalker::open(root, options);
    REQUIRE(copies);
    auto copied = walkAll(*copies);
    REQUIRE(copied.size() == 6);
    CHECK(copied[4].kind == WalkKind::Regular);
    CHECK(copied[4].size == 5);
}

TEST_CASE("TreeWalker refuses a non-directory root and trees deeper than the limit") {
    bale::test::TempPath temp;
    fs::create_directories(temp.path() / "x" / "y" / "z");
    std::ofstream(temp.path() / "file", std::ios::binary) << "x";
    CHECK_FALSE(TreeWalker::open(temp.path() / "file"));

    WalkOptions options;
    options.limits.maxDepth = 2;
    auto walker = TreeWalker::open(temp.path(), options);
    REQUIRE(walker);
    Result<const WalkEntry*> next = nullptr;
    do {
        next = walker->next();
    } while (next && *next != nullptr);
    REQUIRE_FALSE(next);
    CHECK(next.error().kind == ErrorKind::LimitExceeded);
}

#endif
