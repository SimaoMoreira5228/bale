#include "formats/wim/reader.hpp"

#include "io/temp_file.hpp"
#include "wim_builder.ipp"

#include <doctest/doctest.h>

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

Result<wim::Reader> openSpec(const wim::test::TestWim& spec) {
    auto bytes = buildWim(spec);
    TempFile temp{std::span<const std::byte>(bytes)};
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    return wim::Reader::open(std::move(*file), {}, 0);
}

}

TEST_CASE("wim reader rejects a bad signature") {
    std::vector<std::byte> bytes{
        std::byte{'N'},
        std::byte{'O'},
        std::byte{'T'},
        std::byte{'W'},
        std::byte{'I'},
        std::byte{'M'},
        std::byte{'!'},
        std::byte{'!'},
    };
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("wim reader rejects a truncated header") {
    std::vector<std::byte> bytes{
        std::byte{'M'},
        std::byte{'S'},
        std::byte{'W'},
        std::byte{'I'},
        std::byte{'M'},
        std::byte{0},
        std::byte{0},
        std::byte{0},
    };
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
}

TEST_CASE("wim reader rejects split archives") {
    auto bytes = golden("multi.wim");
    // NOTE: part number lives at header offset 40; flipping it to part 2 of
    // 2 marks a split archive without touching any other structure.
    bytes[40] = std::byte{2};
    bytes[42] = std::byte{2};
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Unsupported);
}

TEST_CASE("wim reader rejects an unknown version") {
    auto bytes = golden("basic.wim");
    bytes[12] = std::byte{0xFF};
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Unsupported);
}

TEST_CASE("wim reader rejects ambiguous compression flags") {
    // NOTE: XPRESS and LZX bits together name no single codec.
    wim::test::TestWim spec;
    spec.flags = 0x00020000 | 0x00040000 | 0x00000002;
    spec.chunkSize = 32768;
    auto reader = openSpec(spec);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("wim reader refuses wimlib XPRESS and LZMS goldens") {
    // NOTE: wl_xpress.wim and wl_lzms.wim were captured with
    // wimlib-imagex 1.14.5 (--compress=xpress, --compress=LZMS --solid).
    // Their metadata is compressed, so even open refuses: XPRESS is a
    // different algorithm and LZMS is out of scope. LZX goldens decode
    // (see lzx_test.cpp).
    for (const std::string name : {"wl_xpress.wim", "wl_lzms.wim"}) {
        auto reader = openBytes(golden(name));
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Unsupported);
    }
}

TEST_CASE("wim reader refuses a solid run without a resource marker") {
    // NOTE: dropping the marker entry leaves solid blobs that map to no
    // resource; offsets after the table shift by one entry.
    wim::test::TestWim spec;
    spec.version = 0x0E00;
    spec.solid = true;
    wim::test::TestFile file;
    file.path = "s.txt";
    file.data = {std::byte{'s'}, std::byte{'!'}};
    spec.images[0].files.push_back(file);
    auto bytes = buildWim(spec);
    std::uint64_t lookupOffset = 0;
    std::uint64_t lookupSize = 0;
    for (std::size_t index = 0; index < 7; ++index) {
        lookupSize |= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(bytes[48 + index]))
            << (index * 8);
    }
    for (int shift = 0; shift < 64; shift += 8) {
        lookupOffset |=
            static_cast<std::uint64_t>(
                std::to_integer<std::uint8_t>(bytes[56 + static_cast<std::size_t>(shift) / 8])
            )
            << shift;
    }
    REQUIRE(lookupSize >= 100);
    bytes.erase(
        bytes.begin() + static_cast<std::ptrdiff_t>(lookupOffset),
        bytes.begin() + static_cast<std::ptrdiff_t>(lookupOffset) + 50
    );
    lookupSize -= 50;
    for (std::size_t index = 0; index < 7; ++index) {
        bytes[48 + index] = static_cast<std::byte>((lookupSize >> (index * 8)) & 0xFF);
    }
    std::uint64_t xmlOffset = 0;
    for (int shift = 0; shift < 64; shift += 8) {
        xmlOffset |=
            static_cast<std::uint64_t>(
                std::to_integer<std::uint8_t>(bytes[80 + static_cast<std::size_t>(shift) / 8])
            )
            << shift;
    }
    xmlOffset -= 50;
    for (int shift = 0; shift < 64; shift += 8) {
        bytes[80 + static_cast<std::size_t>(shift) / 8] =
            static_cast<std::byte>((xmlOffset >> shift) & 0xFF);
    }
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("wim reader rejects an out-of-range lookup offset") {
    auto bytes = golden("basic.wim");
    // NOTE: lookup offset lives at header offset 48; pushing it near the end
    // of the file overflows the table without breaking the magic.
    for (int shift = 0; shift < 32; shift += 8) {
        bytes[48 + static_cast<std::size_t>(shift) / 8] = std::byte{0xF0};
    }
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("wim reader rejects image metadata that disagrees with XML") {
    // NOTE: flipping the first IMAGE INDEX digit from 1 to 2 breaks the
    // header/image order contract.
    auto bytes = golden("multi.wim");
    bool patched = false;
    for (std::size_t index = 0; index + 24 < bytes.size(); index += 2) {
        if (bytes[index] == std::byte{'1'} && bytes[index + 1] == std::byte{0} &&
            bytes[index + 2] == std::byte{'"'} && bytes[index + 3] == std::byte{0}) {
            bytes[index] = std::byte{'2'};
            patched = true;
            break;
        }
    }
    REQUIRE(patched);
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("wim reader rejects a directory loop") {
    // NOTE: dir/nested is re-pointed at the root's child block, which the
    // visited set has already seen.
    wim::test::TestWim spec;
    wim::test::TestFile file;
    file.path = "dir/nested/deep.txt";
    file.data = {std::byte{'d'}};
    spec.images[0].files.push_back(file);
    spec.subdirOverride["dir/nested"] = "";
    auto reader = openSpec(spec);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("wim reader treats mismatched hard-link groups as separate files") {
    // NOTE: DISM links same-group dentries only when their content matches;
    // different content must not merge into a hard link.
    wim::test::TestWim spec;
    wim::test::TestFile first;
    first.path = "a.txt";
    first.data = {std::byte{'a'}};
    first.group = 9;
    wim::test::TestFile second;
    second.path = "b.txt";
    second.data = {std::byte{'b'}};
    second.group = 9;
    spec.images[0].files.push_back(first);
    spec.images[0].files.push_back(second);
    auto reader = openSpec(spec);
    REQUIRE(reader);
    REQUIRE(reader->entryCount() == 2);
    for (const auto& entry : reader->entries()) {
        CHECK(entry.kind == wim::EntryKind::Regular);
    }
}

TEST_CASE("wim reader skips encrypted files as other entries") {
    wim::test::TestWim spec;
    wim::test::TestFile file;
    file.path = "secret.txt";
    file.data = {std::byte{'s'}};
    file.attrs = 0x20 | 0x4000;
    spec.images[0].files.push_back(file);
    auto reader = openSpec(spec);
    REQUIRE(reader);
    REQUIRE(reader->entryCount() == 1);
    CHECK(reader->entries()[0].kind == wim::EntryKind::Other);
}

TEST_CASE("wim reader skips unknown reparse tags as other entries") {
    wim::test::TestWim spec;
    wim::test::TestFile file;
    file.path = "dedup.bin";
    file.data = {std::byte{'d'}};
    file.attrs = 0x20 | 0x400;
    file.reparseTag = 0x80000013;
    file.reparseData = {std::byte{1}, std::byte{2}};
    spec.images[0].files.push_back(file);
    auto reader = openSpec(spec);
    REQUIRE(reader);
    REQUIRE(reader->entryCount() == 1);
    CHECK(reader->entries()[0].kind == wim::EntryKind::Other);
}

TEST_CASE("wim reader enforces directory depth") {
    wim::test::TestWim spec;
    wim::test::TestFile file;
    file.path = "a/b/c/d/e.txt";
    file.data = {std::byte{'x'}};
    spec.images[0].files.push_back(file);
    auto bytes = buildWim(spec);
    TempFile temp{std::span<const std::byte>(bytes)};
    REQUIRE(temp.ok());
    auto opened = temp.open();
    REQUIRE(opened);
    wim::Limits limits;
    limits.maxDepth = 3;
    auto reader = wim::Reader::open(std::move(*opened), limits, 0);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::LimitExceeded);
}

TEST_CASE("wim reader rejects an unordered chunk table") {
    // NOTE: the first chunk's stored size is validated eagerly at open, so a
    // shuffled table fails fast with Malformed.
    wim::test::TestWim spec;
    spec.flags = 0x00040002;
    spec.chunkSize = 16;
    spec.corruptTable = true;
    wim::test::TestFile file;
    file.path = "z.bin";
    file.data = std::vector<std::byte>(64, std::byte{'z'});
    spec.images[0].files.push_back(file);
    spec.compressedBlobs.push_back(file.data);
    auto bytes = buildWim(spec);
    TempFile temp{std::span<const std::byte>(bytes)};
    REQUIRE(temp.ok());
    auto opened = temp.open();
    REQUIRE(opened);
    auto reader = wim::Reader::open(std::move(*opened), {}, 0);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}
