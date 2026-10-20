#include "formats/wim/reader.hpp"

#include "io/temp_file.hpp"
#include "wim_builder.ipp"

#include <doctest/doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace bale;
using bale::test::TempFile;

namespace {

std::vector<std::byte> golden(std::string_view name) {
    std::filesystem::path path = std::filesystem::path(FORMAT_GOLDEN_DIR) / "wim" / "data" / name;
    std::ifstream file(path, std::ios::binary);
    REQUIRE(file);

    std::vector<std::byte> bytes;
    char chunk[4096];
    while (file) {
        file.read(chunk, sizeof(chunk));
        auto count = file.gcount();
        for (std::streamsize index = 0; index < count; ++index) {
            bytes.push_back(static_cast<std::byte>(chunk[index]));
        }
    }
    return bytes;
}

Result<wim::Reader> openBytes(const std::vector<std::byte>& bytes, std::uint32_t image = 0) {
    TempFile temp{std::span<const std::byte>(bytes.data(), bytes.size())};
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    return wim::Reader::open(std::move(*file), {}, image);
}

std::vector<std::byte> collect(wim::Reader& reader, const wim::Entry& entry) {
    std::vector<std::byte> scratch(65536);
    std::vector<std::byte> out;
    auto streamed = reader.streamEntry(entry, scratch, [&](std::span<const std::byte> chunk) {
        out.insert(out.end(), chunk.begin(), chunk.end());
        return Result<void>{};
    });
    REQUIRE(streamed);
    return out;
}

const wim::Entry* find(const wim::Reader& reader, std::string_view name) {
    for (const auto& entry : reader.entries()) {
        if (entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

std::uint64_t fnv(const std::vector<std::byte>& data) {
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (std::byte unit : data) {
        hash ^= static_cast<std::uint64_t>(unit);
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

}

TEST_CASE("wim reader lists the basic golden with sizes") {
    // NOTE: tests/formats/wim/data/basic.wim is hermetic output from
    // tests/formats/wim/tools/make_fixtures.py: one stored image plus a
    // COMPRESSED-flag resource whose chunks are all stored raw, an empty
    // file and a 100 KiB file spanning four 32 KiB chunks. wimlib-imagex
    // 1.14.5 accepts it; 7-Zip 26.04 does not (see tools/README).
    auto reader = openBytes(golden("basic.wim"));
    REQUIRE(reader);

    REQUIRE(reader->entryCount() == 6);
    const wim::Entry* hello = find(*reader, "hello.txt");
    REQUIRE(hello != nullptr);
    CHECK(hello->size == 10);
    CHECK(hello->kind == wim::EntryKind::Regular);
    const wim::Entry* big = find(*reader, "big.bin");
    REQUIRE(big != nullptr);
    CHECK(big->size == 100 * 1024);
    const wim::Entry* empty = find(*reader, "empty.txt");
    REQUIRE(empty != nullptr);
    CHECK(empty->size == 0);
    const wim::Entry* nested = find(*reader, "dir/nested");
    REQUIRE(nested != nullptr);
    CHECK(nested->kind == wim::EntryKind::Directory);

    auto data = collect(*reader, *hello);
    std::vector<std::byte> expected{
        std::byte{'h'},
        std::byte{'e'},
        std::byte{'l'},
        std::byte{'l'},
        std::byte{'o'},
        std::byte{' '},
        std::byte{'w'},
        std::byte{'i'},
        std::byte{'m'},
        std::byte{'\n'}
    };
    CHECK(data == expected);
    auto bigData = collect(*reader, *big);
    REQUIRE(bigData.size() == 100 * 1024);
    CHECK(fnv(bigData) == 0xd790ed34c44af235ULL);
}

TEST_CASE("wim reader defaults to the bootable image") {
    // NOTE: multi.wim holds three images with image 2 marked bootable; the
    // default selection rule names the bootable image, --image overrides it.
    auto reader = openBytes(golden("multi.wim"));
    REQUIRE(reader);
    CHECK(reader->selectedImage() == 2);
    REQUIRE(reader->images().size() == 3);
    CHECK(reader->bootImage() == 2);
    CHECK(reader->images()[0].name == "image-1");
    REQUIRE(reader->entryCount() == 2);
    CHECK(find(*reader, "two.txt") != nullptr);
    CHECK(find(*reader, "shared.txt") != nullptr);

    auto first = openBytes(golden("multi.wim"), 1);
    REQUIRE(first);
    CHECK(first->selectedImage() == 1);
    REQUIRE(first->entryCount() == 1);
    CHECK(find(*first, "one.txt") != nullptr);

    auto third = openBytes(golden("multi.wim"), 3);
    REQUIRE(third);
    CHECK(third->selectedImage() == 3);
    const wim::Entry* unicode = find(*third, "ünïcodé.txt");
    REQUIRE(unicode != nullptr);
    auto data = collect(*third, *unicode);
    CHECK(data == collect(*third, *unicode));
}

TEST_CASE("wim reader maps links and streams in the rich golden") {
    // NOTE: rich.wim covers the link/stream rules: a hard-link pair, a
    // symlink, a junction and a named alternate data stream.
    auto reader = openBytes(golden("rich.wim"));
    REQUIRE(reader);

    const wim::Entry* orig = find(*reader, "orig.txt");
    const wim::Entry* link = find(*reader, "link.txt");
    REQUIRE(orig != nullptr);
    REQUIRE(link != nullptr);
    // NOTE: link.txt sorts first in the image, so it carries the data and
    // orig.txt becomes the hard link: first occurrence always wins.
    CHECK(link->kind == wim::EntryKind::Regular);
    CHECK(orig->kind == wim::EntryKind::HardLink);
    CHECK(orig->linkTarget == "link.txt");
    // NOTE: hard links carry no stream of their own; the size matches the
    // first occurrence and extraction resolves through the target.
    CHECK(orig->size == link->size);
    auto linked = collect(*reader, *link);
    CHECK(
        std::string(reinterpret_cast<const char*>(linked.data()), linked.size()) ==
        "linked content\n"
    );

    const wim::Entry* pointer = find(*reader, "pointer.lnk");
    REQUIRE(pointer != nullptr);
    CHECK(pointer->kind == wim::EntryKind::Symlink);
    CHECK(pointer->linkTarget == "/target.txt");

    const wim::Entry* junction = find(*reader, "junction");
    REQUIRE(junction != nullptr);
    CHECK(junction->kind == wim::EntryKind::Symlink);
    CHECK(junction->linkTarget == "C:/windows");

    const wim::Entry* notes = find(*reader, "notes.txt");
    const wim::Entry* hidden = find(*reader, "notes.txt:hidden");
    REQUIRE(notes != nullptr);
    REQUIRE(hidden != nullptr);
    CHECK(hidden->kind == wim::EntryKind::AlternateStream);
    auto showed = collect(*reader, *notes);
    auto stashed = collect(*reader, *hidden);
    CHECK(
        std::string(reinterpret_cast<const char*>(showed.data()), showed.size()) ==
        "default stream\n"
    );
    CHECK(
        std::string(reinterpret_cast<const char*>(stashed.data()), stashed.size()) ==
        "alternate stream\n"
    );
}

TEST_CASE("wim reader decodes blobs packed in a solid resource") {
    // NOTE: solid_stored.wim is hermetic (no real tool writes format-None
    // solid resources): two files concatenated in one solid resource.
    auto reader = openBytes(golden("solid_stored.wim"));
    REQUIRE(reader);
    const wim::Entry* first = find(*reader, "s1.txt");
    const wim::Entry* second = find(*reader, "sub/s2.txt");
    REQUIRE(first != nullptr);
    REQUIRE(second != nullptr);
    auto one = collect(*reader, *first);
    auto two = collect(*reader, *second);
    CHECK(std::string(reinterpret_cast<const char*>(one.data()), one.size()) == "solid one\n");
    CHECK(
        std::string(reinterpret_cast<const char*>(two.data()), two.size()) ==
        "solid two is a bit longer\n"
    );
}

TEST_CASE("wim reader opens the wimlib stored golden") {
    // NOTE: wl_none.wim was captured with wimlib-imagex 1.14.5
    // (--compress=none) from a tree with a hard link and a symlink.
    auto reader = openBytes(golden("wl_none.wim"));
    REQUIRE(reader);
    const wim::Entry* hard = find(*reader, "hard.txt");
    REQUIRE(hard != nullptr);
    CHECK(hard->kind == wim::EntryKind::HardLink);
    CHECK(hard->linkTarget == "a.txt");
    const wim::Entry* soft = find(*reader, "soft.lnk");
    REQUIRE(soft != nullptr);
    CHECK(soft->kind == wim::EntryKind::Symlink);
    CHECK(soft->linkTarget == "b.txt");
    auto data = collect(*reader, *find(*reader, "a.txt"));
    CHECK(std::string(reinterpret_cast<const char*>(data.data()), data.size()) == "alpha\n");
}

TEST_CASE("wim reader rejects an out-of-range image index") {
    auto bytes = golden("multi.wim");
    auto reader = openBytes(bytes, 4);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("wim reader enforces entry limits") {
    wim::test::TestWim spec;
    wim::test::TestFile file;
    file.path = "a.txt";
    file.data = {std::byte{'x'}};
    spec.images[0].files.push_back(file);
    wim::Limits limits;
    limits.maxEntries = 1;
    auto bytes = buildWim(spec);
    TempFile temp{std::span<const std::byte>(bytes)};
    REQUIRE(temp.ok());
    auto opened = temp.open();
    REQUIRE(opened);
    auto parsed = wim::Reader::open(std::move(*opened), limits, 0);
    REQUIRE_FALSE(parsed);
    CHECK(parsed.error().kind == ErrorKind::LimitExceeded);
}

TEST_CASE("wim reader refuses a compressed stream per entry") {
    // NOTE: stored metadata with one LZX-flagged data blob: open succeeds so
    // list works, and only the compressed stream refuses with Unsupported.
    wim::test::TestWim spec;
    spec.flags = 0x00040002;
    spec.chunkSize = 32768;
    wim::test::TestFile file;
    file.path = "z.bin";
    file.data = std::vector<std::byte>(100, std::byte{'z'});
    spec.images[0].files.push_back(file);
    std::vector<std::byte> blob = file.data;
    spec.compressedBlobs.push_back(blob);
    auto bytes = buildWim(spec);
    TempFile temp{std::span<const std::byte>(bytes)};
    REQUIRE(temp.ok());
    auto opened = temp.open();
    REQUIRE(opened);
    auto reader = wim::Reader::open(std::move(*opened), {}, 0);
    REQUIRE(reader);
    REQUIRE(reader->entryCount() == 1);
    std::vector<std::byte> scratch(64);
    auto streamed =
        reader->streamEntry(reader->entries()[0], scratch, [](std::span<const std::byte>) {
            return Result<void>{};
        });
    REQUIRE_FALSE(streamed);
    CHECK(streamed.error().kind == ErrorKind::Unsupported);
}
