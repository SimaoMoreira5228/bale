#ifndef _WIN32

#include "extract/extractor.hpp"

#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>

using namespace bale;
using namespace std::literals;

namespace fs = std::filesystem;

namespace {

class TempTree {
  public:
    TempTree() {
        fs::create_directories(root());
        fs::create_directories(outside());
    }

    [[nodiscard]] fs::path root() const {
        return base_.path() / "root";
    }

    [[nodiscard]] fs::path outside() const {
        return base_.path() / "outside";
    }

  private:
    bale::test::TempPath base_;
};

ArchivePath at(std::string_view path) {
    return ArchivePath{
        .path = path,
        .depth = static_cast<std::uint32_t>(std::ranges::count(path, '/') + 1),
    };
}

std::span<const std::byte> bytes(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

std::string readFile(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void writeFile(const fs::path& path, std::string_view text) {
    std::ofstream out(path, std::ios::binary);
    out << text;
}

std::vector<std::string> listing(const fs::path& directory) {
    std::vector<std::string> names;
    for (const auto& entry : fs::directory_iterator(directory)) {
        names.push_back(entry.path().filename().string());
    }
    std::ranges::sort(names);
    return names;
}

std::uint32_t modeOf(const fs::path& path) {
    struct stat status{};
    REQUIRE(::lstat(path.c_str(), &status) == 0);
    return static_cast<std::uint32_t>(status.st_mode) & 07777;
}

Result<EntryResult> extractFile(
    Extractor& extractor,
    std::string_view path,
    std::string_view content,
    const EntryMetadata& metadata = {}
) {
    auto pending = extractor.beginFile(at(path), metadata);
    if (!pending) {
        return std::unexpected(pending.error());
    }

    auto written = pending->write(bytes(content));
    if (!written) {
        return std::unexpected(written.error());
    }
    return pending->commit();
}

EntryMetadata withMode(std::uint32_t mode) {
    EntryMetadata metadata;
    metadata.mode = mode;
    return metadata;
}

Extractor
openExtractor(const TempTree& tree, const std::function<void(ExtractPolicy&)>& configure = {}) {
    ExtractPolicy policy;
    if (configure) {
        configure(policy);
    }

    auto extractor = Extractor::open(tree.root(), policy);
    REQUIRE(extractor);
    return std::move(*extractor);
}

}

TEST_CASE("Extractor writes nested entries with masked modes and restored mtimes") {
    TempTree tree;
    auto extractor = openExtractor(tree);

    REQUIRE(extractor.createDirectory(at("docs"), withMode(0700)));

    auto pending = extractor.beginFile(
        at("docs/guide/intro.txt"),
        EntryMetadata{
            .mode = 0666,
            .mtimeNanoseconds = -1'500'000'000,
        }
    );
    REQUIRE(pending);
    CHECK_FALSE(pending->skipping());
    REQUIRE(pending->write(bytes("hello ")));
    REQUIRE(pending->write(bytes("world")));
    CHECK_FALSE(fs::exists(tree.root() / "docs/guide/intro.txt"));
    auto committed = pending->commit();
    REQUIRE(committed);
    CHECK(committed->outcome == EntryOutcome::Extracted);
    CHECK_FALSE(pending->commit());

    const fs::path file = tree.root() / "docs/guide/intro.txt";
    CHECK(readFile(file) == "hello world");
    CHECK(modeOf(file) == 0644);
    CHECK(listing(tree.root() / "docs/guide") == std::vector<std::string>{"intro.txt"});

    struct stat status{};
    REQUIRE(::stat(file.c_str(), &status) == 0);
    CHECK(status.st_mtim.tv_sec == -2);
    CHECK(status.st_mtim.tv_nsec == 500'000'000);

    auto again = extractor.createDirectory(at("docs"), withMode(0750));
    REQUIRE(again);
    CHECK(again->outcome == EntryOutcome::Extracted);
    CHECK(modeOf(tree.root() / "docs") == 0750);

    auto overFile = extractor.createDirectory(at("docs/guide/intro.txt"));
    REQUIRE_FALSE(overFile);
    CHECK(overFile.error().kind == ErrorKind::AlreadyExists);

    auto throughFile = extractor.beginFile(at("docs/guide/intro.txt/inner"));
    REQUIRE_FALSE(throughFile);
    CHECK(throughFile.error().kind == ErrorKind::AlreadyExists);

    CHECK(extractor.budget().entries() == 5);
    CHECK(extractor.budget().totalBytes() == 11);
}

TEST_CASE("Extractor never follows a symlink planted in the destination") {
    TempTree tree;
    fs::create_directory_symlink(tree.outside(), tree.root() / "escape");
    writeFile(tree.outside() / "secret", "keep");
    fs::create_symlink(tree.outside() / "secret", tree.root() / "secret-link");

    for (auto overwrite :
         {OverwritePolicy::Never, OverwritePolicy::Replace, OverwritePolicy::Skip}) {
        const int overwriteValue = static_cast<int>(overwrite);
        CAPTURE(overwriteValue);
        auto extractor = openExtractor(tree, [&](ExtractPolicy& policy) {
            policy.overwrite = overwrite;
        });

        auto file = extractor.beginFile(at("escape/planted"));
        REQUIRE_FALSE(file);
        CHECK(file.error().kind == ErrorKind::UnsafePath);

        auto nested = extractor.createDirectory(at("escape/a/b"));
        REQUIRE_FALSE(nested);
        CHECK(nested.error().kind == ErrorKind::UnsafePath);

        auto directory = extractor.createDirectory(at("escape"));
        if (overwrite == OverwritePolicy::Skip) {
            REQUIRE(directory);
            CHECK(directory->outcome == EntryOutcome::Skipped);
        } else {
            REQUIRE_FALSE(directory);
            CHECK(directory.error().kind == ErrorKind::AlreadyExists);
        }

        auto overLink = extractFile(extractor, "secret-link", "overwritten");
        if (overwrite == OverwritePolicy::Skip) {
            REQUIRE(overLink);
            CHECK(overLink->outcome == EntryOutcome::Skipped);
        } else {
            REQUIRE_FALSE(overLink);
            CHECK(overLink.error().kind == ErrorKind::AlreadyExists);
        }
    }

    CHECK(listing(tree.outside()) == std::vector<std::string>{"secret"});
    CHECK(readFile(tree.outside() / "secret") == "keep");
    CHECK(fs::is_symlink(tree.root() / "secret-link"));
    CHECK(listing(tree.root()) == std::vector<std::string>{"escape", "secret-link"});
}

TEST_CASE("Extractor refuses symlink entries by default so an archive cannot plant one") {
    TempTree tree;
    auto extractor = openExtractor(tree);

    auto link = extractor.createSymlink(at("escape"), tree.outside().string());
    REQUIRE_FALSE(link);
    CHECK(link.error().kind == ErrorKind::UnsafePath);

    auto contained = extractor.createSymlink(at("inner"), "sub");
    REQUIRE_FALSE(contained);
    CHECK(contained.error().kind == ErrorKind::UnsafePath);

    REQUIRE(extractFile(extractor, "escape/file", "data"));
    CHECK(fs::is_directory(fs::symlink_status(tree.root() / "escape")));
    CHECK(readFile(tree.root() / "escape/file") == "data");
    CHECK(listing(tree.outside()).empty());

    auto skipping = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.symlinks = SymlinkPolicy::Skip;
    });
    auto skipped = skipping.createSymlink(at("other"), "escape");
    REQUIRE(skipped);
    CHECK(skipped->outcome == EntryOutcome::Skipped);
    CHECK_FALSE(skipped->reason.empty());
    CHECK_FALSE(fs::exists(fs::symlink_status(tree.root() / "other")));
}

TEST_CASE("Extractor does not follow a contained symlink created by an earlier entry") {
    TempTree tree;
    auto extractor = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.symlinks = SymlinkPolicy::AllowContained;
    });

    REQUIRE(extractor.createDirectory(at("real")));
    auto link = extractor.createSymlink(at("alias"), "real");
    REQUIRE(link);
    CHECK(link->outcome == EntryOutcome::Extracted);
    CHECK(fs::read_symlink(tree.root() / "alias") == "real");

    auto through = extractor.beginFile(at("alias/file"));
    REQUIRE_FALSE(through);
    CHECK(through.error().kind == ErrorKind::UnsafePath);

    auto nested = extractor.createDirectory(at("alias/sub"));
    REQUIRE_FALSE(nested);
    CHECK(nested.error().kind == ErrorKind::UnsafePath);

    auto overLink = extractor.createSymlink(at("alias"), "real");
    REQUIRE_FALSE(overLink);
    CHECK(overLink.error().kind == ErrorKind::AlreadyExists);

    CHECK(listing(tree.root() / "real").empty());
    CHECK(listing(tree.root()) == std::vector<std::string>{"alias", "real"});
}

TEST_CASE("Extractor keeps contained symlink targets inside the root") {
    TempTree tree;
    auto extractor = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.symlinks = SymlinkPolicy::AllowContained;
    });

    struct Case {
        std::string_view path;
        std::string_view target;
        std::optional<std::string_view> stored;
    };
    const Case cases[] = {
        {"up", "../x", std::nullopt},
        {"absolute", "/etc/passwd", std::nullopt},
        {"drive", "C:/Windows", std::nullopt},
        {"backslash", "..\\x", std::nullopt},
        {"empty", "", std::nullopt},
        {"collapsed", "a/../b", "b"},
        {"self", "./.", "."},
        {"dir/sibling", "../top", "../top"},
        {"dir/climb", "../../x", std::nullopt},
        {"dir/detour", "x/../../y", "../y"},
        {"dir/deep/back", "a/../../../z/", "../../z"},
        {"dir/deep/up", "../..", "../.."},
        {"dir/deep/escape", "../../a/../..", std::nullopt},
    };

    for (const Case& test : cases) {
        CAPTURE(test.path);
        auto result = extractor.createSymlink(at(test.path), test.target);
        const fs::path where = tree.root() / test.path;
        if (!test.stored) {
            REQUIRE_FALSE(result);
            CHECK(result.error().kind == ErrorKind::UnsafePath);
            CHECK_FALSE(fs::exists(fs::symlink_status(where)));
            continue;
        }

        REQUIRE(result);
        CHECK(fs::read_symlink(where).string() == *test.stored);
    }

    CHECK(listing(tree.root() / "dir") == std::vector<std::string>{"deep", "detour", "sibling"});
}

TEST_CASE("Extractor applies the overwrite policy atomically at commit") {
    TempTree tree;
    writeFile(tree.root() / "existing", "old");
    fs::create_directory(tree.root() / "folder");

    auto never = openExtractor(tree);
    auto early = never.beginFile(at("existing"));
    REQUIRE_FALSE(early);
    CHECK(early.error().kind == ErrorKind::AlreadyExists);

    auto raced = never.beginFile(at("late"));
    REQUIRE(raced);
    writeFile(tree.root() / "late", "theirs");
    REQUIRE(raced->write(bytes("ours")));
    auto racedCommit = raced->commit();
    REQUIRE_FALSE(racedCommit);
    CHECK(racedCommit.error().kind == ErrorKind::AlreadyExists);
    CHECK(readFile(tree.root() / "late") == "theirs");

    auto replace = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.overwrite = OverwritePolicy::Replace;
    });
    auto replaced = extractFile(replace, "existing", "new");
    REQUIRE(replaced);
    CHECK(replaced->outcome == EntryOutcome::Extracted);
    CHECK(readFile(tree.root() / "existing") == "new");

    auto overDirectory = replace.beginFile(at("folder"));
    REQUIRE_FALSE(overDirectory);
    CHECK(overDirectory.error().kind == ErrorKind::AlreadyExists);

    auto skip = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.overwrite = OverwritePolicy::Skip;
    });
    auto skipped = skip.beginFile(at("existing"));
    REQUIRE(skipped);
    CHECK(skipped->skipping());
    REQUIRE(skipped->write(bytes("ignored")));
    auto skipCommit = skipped->commit();
    REQUIRE(skipCommit);
    CHECK(skipCommit->outcome == EntryOutcome::Skipped);
    CHECK(skip.budget().totalBytes() == 7);

    auto skipRace = skip.beginFile(at("late2"));
    REQUIRE(skipRace);
    CHECK_FALSE(skipRace->skipping());
    writeFile(tree.root() / "late2", "theirs");
    auto skipRaceCommit = skipRace->commit();
    REQUIRE(skipRaceCommit);
    CHECK(skipRaceCommit->outcome == EntryOutcome::Skipped);
    CHECK(readFile(tree.root() / "late2") == "theirs");

    CHECK(readFile(tree.root() / "existing") == "new");
    CHECK(listing(tree.root()) == std::vector<std::string>{"existing", "folder", "late", "late2"});
}

TEST_CASE("Uncommitted or failed pending files leave nothing behind") {
    TempTree tree;
    Limits limits;
    limits.maxEntryBytes = 10;
    limits.maxEntries = 3;
    auto extractor = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.limits = limits;
    });

    {
        auto pending = extractor.beginFile(at("dir/abandoned"));
        REQUIRE(pending);
        REQUIRE(pending->write(bytes("partial")));
        CHECK(listing(tree.root() / "dir").size() == 1);

        auto moved = std::move(*pending);
        REQUIRE(moved.write(bytes("!")));
    }
    CHECK(listing(tree.root() / "dir").empty());

    auto bomb = extractor.beginFile(at("dir/bomb"));
    REQUIRE(bomb);
    REQUIRE(bomb->write(bytes("12345678")));
    auto overflow = bomb->write(bytes("90a"));
    REQUIRE_FALSE(overflow);
    CHECK(overflow.error().kind == ErrorKind::LimitExceeded);
    CHECK_FALSE(bomb->write(bytes("x")));
    CHECK_FALSE(bomb->commit());
    CHECK(listing(tree.root() / "dir").empty());

    REQUIRE(extractFile(extractor, "dir/fits", "0123456789"));
    auto entries = extractor.createDirectory(at("more"));
    REQUIRE_FALSE(entries);
    CHECK(entries.error().kind == ErrorKind::LimitExceeded);
    CHECK(listing(tree.root() / "dir") == std::vector<std::string>{"fits"});
}

TEST_CASE("Extractor strips privileged mode bits unless the policy allows them") {
    TempTree tree;
    auto extractor = openExtractor(tree);

    REQUIRE(extractFile(extractor, "setuid", "x", withMode(06777)));
    CHECK(modeOf(tree.root() / "setuid") == 0755);
    REQUIRE(extractor.createDirectory(at("sticky"), withMode(01557)));
    CHECK(modeOf(tree.root() / "sticky") == 0755);
    REQUIRE(extractFile(extractor, "locked", "x", withMode(0400)));
    CHECK(modeOf(tree.root() / "locked") == 0400);

    auto permissive = openExtractor(tree, [](ExtractPolicy& policy) {
        policy.restoreSpecialModeBits = true;
        policy.umask = 0;
    });
    REQUIRE(extractFile(permissive, "kept", "x", withMode(04777)));
    CHECK(modeOf(tree.root() / "kept") == 04777);
}

TEST_CASE("Extractor links only to regular files it extracted in this session") {
    TempTree tree;
    writeFile(tree.root() / "preexisting", "theirs");
    fs::create_symlink("original", tree.root() / "symlink");
    auto extractor = openExtractor(tree);

    REQUIRE(extractFile(extractor, "dir/original", "shared"));
    REQUIRE(extractor.createDirectory(at("folder")));

    auto linked = extractor.createHardLink(at("other/copy"), at("dir/original"));
    REQUIRE(linked);
    CHECK(linked->outcome == EntryOutcome::Extracted);
    CHECK(fs::equivalent(tree.root() / "other/copy", tree.root() / "dir/original"));
    CHECK(listing(tree.root() / "other") == std::vector<std::string>{"copy"});

    for (std::string_view target :
         {"preexisting", "missing", "nowhere/file", "folder", "symlink"}) {
        CAPTURE(target);
        auto refused = extractor.createHardLink(at("refused"), at(target));
        REQUIRE_FALSE(refused);
        CHECK(refused.error().kind == ErrorKind::UnsafePath);
    }
    CHECK_FALSE(fs::exists(fs::symlink_status(tree.root() / "refused")));

    auto existing = extractor.createHardLink(at("other/copy"), at("dir/original"));
    REQUIRE_FALSE(existing);
    CHECK(existing.error().kind == ErrorKind::AlreadyExists);

    auto other = openExtractor(tree);
    auto stale = other.createHardLink(at("again"), at("dir/original"));
    REQUIRE_FALSE(stale);
    CHECK(stale.error().kind == ErrorKind::UnsafePath);

    auto noLinks = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.hardLinks = HardLinkPolicy::Refuse;
    });
    CHECK_FALSE(noLinks.createHardLink(at("again"), at("dir/original")));
}

TEST_CASE("Extractor refuses hostile paths and never creates special files") {
    TempTree tree;
    auto extractor = openExtractor(tree);

    for (auto path : {".."sv, "a/../../b"sv, "a//b"sv, "./a"sv, "a/"sv, "a/b\0c"sv}) {
        CAPTURE(path);
        auto file = extractor.beginFile(at(path));
        REQUIRE_FALSE(file);
        CHECK(file.error().kind == ErrorKind::UnsafePath);
    }
    const std::string longName(maxLeafBytes + 1, 'n');
    CHECK_FALSE(extractor.createDirectory(at(longName)));

    auto fifo = extractor.skipOrRefuseSpecialFile(at("pipe"), SpecialFileKind::Fifo);
    REQUIRE(fifo);
    CHECK(fifo->outcome == EntryOutcome::Skipped);
    CHECK_FALSE(fifo->reason.empty());

    auto strict = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.specialFiles = SpecialFilePolicy::Refuse;
    });
    auto device = strict.skipOrRefuseSpecialFile(at("disk"), SpecialFileKind::BlockDevice);
    REQUIRE_FALSE(device);
    CHECK(device.error().kind == ErrorKind::Unsupported);

    CHECK(listing(tree.root()).empty());
    CHECK(listing(tree.outside()).empty());
}

TEST_CASE("Extractor reports case-fold collisions when the target ignores case") {
    TempTree tree;
    auto folding = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.caseInsensitive = true;
    });

    REQUIRE(extractFile(folding, "Docs/Readme.txt", "first"));
    auto collision = folding.beginFile(at("docs/README.TXT"));
    REQUIRE_FALSE(collision);
    CHECK(collision.error().kind == ErrorKind::UnsafePath);

    auto directory = folding.createDirectory(at("DOCS"));
    REQUIRE(directory);
    auto directoryCollision = folding.createDirectory(at("docs"));
    REQUIRE_FALSE(directoryCollision);
    CHECK(directoryCollision.error().kind == ErrorKind::UnsafePath);

    auto repeat = folding.beginFile(at("Docs/Readme.txt"));
    REQUIRE_FALSE(repeat);
    CHECK(repeat.error().kind == ErrorKind::AlreadyExists);

    auto sensitive = openExtractor(tree, [&](ExtractPolicy& policy) {
        policy.caseInsensitive = false;
    });
    REQUIRE(extractFile(sensitive, "Docs/README.TXT", "second"));
    CHECK(readFile(tree.root() / "Docs/Readme.txt") == "first");
}

#endif
