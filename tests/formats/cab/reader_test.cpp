#include "formats/cab/reader.hpp"

#include "cab_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace bale;
using bale::test::TempFile;

namespace {

// NOTE: minimal cabinet writer for reader tests. Container shapes mirror
// [MS-CAB]; all payload bytes here are either literal stored data or the
// triple-validated streams from cab_fixture.hpp, never fresh LZX output.

using Bytes = std::vector<std::byte>;

void put16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>(value & 0xFF));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
}

void put32(Bytes& out, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xFF));
    }
}

std::uint32_t checksumBlock(
    std::uint64_t compressed,
    std::uint64_t uncompressed,
    std::span<const std::byte> payload
) {
    std::uint32_t sum =
        (static_cast<std::uint32_t>(uncompressed) << 16) | static_cast<std::uint32_t>(compressed);
    auto at = [](std::span<const std::byte> part, std::size_t index) {
        return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(part[index])) |
            (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(part[index + 1])) << 8) |
            (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(part[index + 2])) << 16) |
            (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(part[index + 3])) << 24);
    };
    std::size_t index = 0;
    while (index + 4 <= payload.size()) {
        sum ^= at(payload, index);
        index += 4;
    }
    std::uint32_t residue = 0;
    while (index < payload.size()) {
        residue = (residue << 8) | static_cast<std::uint8_t>(payload[index]);
        ++index;
    }
    return sum ^ residue;
}

struct TestBlock {
    Bytes payload;
    std::uint64_t uncompressed = 0;
    std::uint32_t checksumOverride = 0;
    bool skipChecksum = false;
};

struct TestFolder {
    std::uint16_t method = 0;
    unsigned windowBits = 15;
    std::vector<TestBlock> blocks;
    std::uint8_t folderReserve = 0;
    std::uint8_t dataReserve = 0;
};

struct TestFile {
    std::string name = "f.txt";
    std::uint32_t folder = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint16_t attribs = 0x20;
};

struct TestCab {
    std::vector<TestFolder> folders = {{}};
    std::vector<TestFile> files = {{"f.txt", 0, 0, 0, 0x20}};
    std::uint16_t flags = 0;
    std::vector<std::string> prevLabels;
    std::vector<std::string> nextLabels;
    Bytes cabinetReserve;
};

Bytes buildCab(TestCab spec) {
    Bytes foldersBytes;
    for (const auto& folder : spec.folders) {
        put32(foldersBytes, 0); // data offset patched below
        put16(foldersBytes, static_cast<std::uint16_t>(folder.blocks.size()));
        std::uint16_t type = static_cast<std::uint16_t>(folder.method | (folder.windowBits << 8));
        put16(foldersBytes, type);
        foldersBytes.insert(foldersBytes.end(), folder.folderReserve, std::byte{0xA5});
    }
    Bytes filesBytes;
    for (const auto& file : spec.files) {
        put32(filesBytes, static_cast<std::uint32_t>(file.size));
        put32(filesBytes, static_cast<std::uint32_t>(file.offset));
        put16(filesBytes, static_cast<std::uint16_t>(file.folder));
        put16(filesBytes, 0x52A4); // 2021-05-04
        put16(filesBytes, 0x63C5); // 12:30:10
        put16(filesBytes, file.attribs);
        for (char c : file.name) {
            filesBytes.push_back(static_cast<std::byte>(c));
        }
        filesBytes.push_back(std::byte{0});
    }

    std::uint64_t headerSize = 36;
    if ((spec.flags & 0x0004) != 0) {
        headerSize += 4 + spec.cabinetReserve.size();
    }
    for (const auto& label : spec.prevLabels) {
        headerSize += label.size() + 1;
    }
    for (const auto& label : spec.nextLabels) {
        headerSize += label.size() + 1;
    }
    std::uint64_t filesOffset = headerSize + foldersBytes.size();
    std::uint64_t dataStart = filesOffset + filesBytes.size();

    // Lay out the data blocks and remember each folder's start.
    Bytes dataBytes;
    std::vector<std::uint32_t> folderStarts;
    for (const auto& folder : spec.folders) {
        folderStarts.push_back(static_cast<std::uint32_t>(dataStart + dataBytes.size()));
        for (const auto& block : folder.blocks) {
            std::uint32_t checksum = block.skipChecksum
                ? 0
                : checksumBlock(block.payload.size(), block.uncompressed, block.payload);
            if (block.checksumOverride != 0) {
                checksum = block.checksumOverride;
            }
            put32(dataBytes, checksum);
            put16(dataBytes, static_cast<std::uint16_t>(block.payload.size()));
            put16(dataBytes, static_cast<std::uint16_t>(block.uncompressed));
            dataBytes.insert(dataBytes.end(), folder.dataReserve, std::byte{0x5A});
            dataBytes.insert(dataBytes.end(), block.payload.begin(), block.payload.end());
        }
    }

    // Patch folder data offsets.
    std::size_t at = 0;
    for (std::size_t i = 0; i < spec.folders.size(); ++i) {
        std::uint32_t start = folderStarts[i];
        for (int shift = 0; shift < 32; shift += 8) {
            foldersBytes[at++] = static_cast<std::byte>((start >> shift) & 0xFF);
        }
        at += std::size_t{4} + spec.folders[i].folderReserve;
    }

    Bytes out;
    out.push_back(std::byte{'M'});
    out.push_back(std::byte{'S'});
    out.push_back(std::byte{'C'});
    out.push_back(std::byte{'F'});
    put32(out, 0); // reserved1
    put32(out, 0); // cabinet size patched below
    put32(out, 0); // reserved2
    put32(out, static_cast<std::uint32_t>(filesOffset));
    put32(out, 0); // reserved3
    out.push_back(std::byte{3}); // version minor
    out.push_back(std::byte{1}); // version major
    put16(out, static_cast<std::uint16_t>(spec.folders.size()));
    put16(out, static_cast<std::uint16_t>(spec.files.size()));
    put16(out, spec.flags);
    put16(out, 0); // setID
    put16(out, 0); // iCabinet
    // Reserve sizes + cabinet reserve come right after the fixed header when
    // the flag is set; the builder only emits them in that case.
    if ((spec.flags & 0x0004) != 0) {
        put16(out, static_cast<std::uint16_t>(spec.cabinetReserve.size()));
        out.push_back(
            spec.folders.empty() ? std::byte{0} : std::byte{spec.folders[0].folderReserve}
        );
        out.push_back(spec.folders.empty() ? std::byte{0} : std::byte{spec.folders[0].dataReserve});
        out.insert(out.end(), spec.cabinetReserve.begin(), spec.cabinetReserve.end());
    }
    for (const auto& label : spec.prevLabels) {
        for (char c : label) {
            out.push_back(static_cast<std::byte>(c));
        }
        out.push_back(std::byte{0});
    }
    for (const auto& label : spec.nextLabels) {
        for (char c : label) {
            out.push_back(static_cast<std::byte>(c));
        }
        out.push_back(std::byte{0});
    }
    out.insert(out.end(), foldersBytes.begin(), foldersBytes.end());
    out.insert(out.end(), filesBytes.begin(), filesBytes.end());
    out.insert(out.end(), dataBytes.begin(), dataBytes.end());

    std::uint32_t total = static_cast<std::uint32_t>(out.size());
    for (int shift = 0; shift < 32; shift += 8) {
        out[std::size_t{8} + static_cast<std::size_t>(shift) / std::size_t{8}] =
            static_cast<std::byte>((total >> shift) & 0xFF);
    }
    return out;
}

Result<cab::Reader> openBytes(const Bytes& bytes, const cab::Limits& limits = {}) {
    TempFile temp(std::span<const std::byte>(bytes.data(), bytes.size()));
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    return cab::Reader::open(std::move(*file), limits);
}

Bytes collect(cab::Reader& reader, const cab::Entry& entry, std::size_t scratchSize = 64) {
    std::vector<std::byte> scratch(scratchSize);
    Bytes out;
    auto streamed = reader.streamEntry(entry, scratch, [&](std::span<const std::byte> chunk) {
        out.insert(out.end(), chunk.begin(), chunk.end());
        return Result<void>{};
    });
    REQUIRE(streamed);
    return out;
}

TEST_CASE("cab reader opens the embedded cabinets") {
    SUBCASE("micro cabinet") {
        Bytes bytes(cab::test::kCabMicroMatch.begin(), cab::test::kCabMicroMatch.end());
        auto reader = openBytes(bytes);
        REQUIRE(reader);
        auto entries = reader->entries();
        REQUIRE(entries.size() == 1);
        CHECK(entries[0].name == "micro_match.txt");
        CHECK(entries[0].size == cab::test::kLzxMicroMatchOut.size());
        auto data = collect(*reader, entries[0]);
        Bytes expected(cab::test::kLzxMicroMatchOut.begin(), cab::test::kLzxMicroMatchOut.end());
        CHECK(data == expected);
    }

    SUBCASE("slots 8/9 cabinet") {
        Bytes bytes(cab::test::kCabSlots89.begin(), cab::test::kCabSlots89.end());
        auto reader = openBytes(bytes);
        REQUIRE(reader);
        auto entries = reader->entries();
        REQUIRE(entries.size() == 1);
        auto data = collect(*reader, entries[0], 7);
        Bytes expected(cab::test::kLzxSlots89Out.begin(), cab::test::kLzxSlots89Out.end());
        CHECK(data == expected);
    }
}

TEST_CASE("cab reader extracts an LZX folder split across CFDATA blocks") {
    TestCab spec;
    auto stream = Bytes(cab::test::kLzxSplitStream.begin(), cab::test::kLzxSplitStream.end());
    // NOTE: the historical split point is byte 18; the decoder must resume
    // bit-exactly across the CFDATA boundary.
    TestFolder folder;
    folder.method = 3;
    folder.blocks = {
        {Bytes(stream.begin(), stream.begin() + 18), 4721},
        {Bytes(stream.begin() + 18, stream.end()), 4279},
    };
    spec.folders = {folder};
    spec.files = {{"v\\rep2.txt", 0, 0, 9000, 0x20}};
    auto reader = openBytes(buildCab(spec));
    REQUIRE(reader);
    auto entries = reader->entries();
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].name == "v\\rep2.txt");
    auto data = collect(*reader, entries[0], 19);
    REQUIRE(data.size() == cab::test::kLzxSplitOutSize);
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (std::byte item : data) {
        hash ^= static_cast<std::uint64_t>(item);
        hash *= 0x100000001b3ULL;
    }
    CHECK(hash == cab::test::kLzxSplitOutHash);
}

TEST_CASE("cab reader extracts stored and MSZIP folders") {
    TestCab spec;
    TestFolder stored;
    stored.blocks = {{{std::byte{'h'}, std::byte{'i'}}, 2}};
    TestFolder zipped;
    zipped.method = 1;
    auto stream = Bytes(cab::test::kMszipBasicStream.begin(), cab::test::kMszipBasicStream.end());
    zipped.blocks = {{stream, cab::test::kMszipBasicOutSize}};
    spec.folders = {stored, zipped};
    spec.files = {
        {"a.txt", 0, 0, 2, 0x20},
        {"b.bin", 1, 0, cab::test::kMszipBasicOutSize, 0x20},
    };
    auto reader = openBytes(buildCab(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 2);
    auto first = collect(*reader, reader->entries()[0]);
    CHECK(first == Bytes{std::byte{'h'}, std::byte{'i'}});
    auto second = collect(*reader, reader->entries()[1], 511);
    REQUIRE(second.size() == cab::test::kMszipBasicOutSize);
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (std::byte item : second) {
        hash ^= static_cast<std::uint64_t>(item);
        hash *= 0x100000001b3ULL;
    }
    CHECK(hash == cab::test::kMszipBasicOutHash);
}

TEST_CASE("cab reader switches sessions across folders in file order") {
    TestCab spec;
    auto stream =
        Bytes(cab::test::kLzxMicroMatchStream.begin(), cab::test::kLzxMicroMatchStream.end());
    TestFolder lzx;
    lzx.method = 3;
    lzx.blocks = {{stream, cab::test::kLzxMicroMatchOut.size()}};
    TestFolder stored;
    stored.blocks = {{{std::byte{'x'}}, 1}};
    spec.folders = {lzx, stored};
    spec.files = {
        {"one.txt", 0, 0, cab::test::kLzxMicroMatchOut.size(), 0x20},
        {"two.txt", 1, 0, 1, 0x20},
        // A second file in the first folder forces a backwards seek, which
        // restarts that folder's session from its first block.
        {"three.txt", 0, 0, 1, 0x20},
    };
    auto reader = openBytes(buildCab(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 3);
    auto one = collect(*reader, reader->entries()[0]);
    CHECK(one.size() == cab::test::kLzxMicroMatchOut.size());
    auto two = collect(*reader, reader->entries()[1]);
    CHECK(two == Bytes{std::byte{'x'}});
    auto three = collect(*reader, reader->entries()[2]);
    REQUIRE(three.size() == 1);
    CHECK(three[0] == one[0]);
}

TEST_CASE("cab reader reports directories without touching folder data") {
    TestCab spec;
    spec.folders = {{}};
    spec.folders[0].blocks = {{{std::byte{'q'}}, 1}};
    spec.files = {{"docs", 0, 0, 0, 0x10}};
    auto reader = openBytes(buildCab(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 1);
    CHECK(reader->entries()[0].directory);
    auto data = collect(*reader, reader->entries()[0]);
    CHECK(data.empty());
}

TEST_CASE("cab reader converts DOS timestamps") {
    TestCab spec;
    spec.files = {{"f.txt", 0, 0, 1, 0x20}};
    spec.folders[0].blocks = {{{std::byte{'q'}}, 1}};
    auto reader = openBytes(buildCab(spec));
    REQUIRE(reader);
    CHECK(reader->entries()[0].mtimeSeconds == cab::dosToUnix(0x52A4, 0x63C5));
    CHECK(reader->entries()[0].mtimeSeconds != 0);
}

TEST_CASE("cab reader rejects a bad signature") {
    Bytes bytes{
        std::byte{'N'},
        std::byte{'O'},
        std::byte{'T'},
        std::byte{'C'},
        std::byte{'A'},
        std::byte{'B'},
        std::byte{'!'},
        std::byte{'!'},
    };
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("cab reader rejects a truncated header") {
    Bytes bytes{
        std::byte{'M'},
        std::byte{'S'},
        std::byte{'C'},
        std::byte{'F'},
        std::byte{0},
    };
    auto reader = openBytes(bytes);
    REQUIRE_FALSE(reader);
}

TEST_CASE("cab reader rejects unknown and quantum methods") {
    for (std::uint16_t method : {std::uint16_t{2}, std::uint16_t{7}}) {
        TestCab spec;
        spec.folders[0].method = method;
        spec.folders[0].windowBits = method == 2 ? 16 : 0;
        spec.folders[0].blocks = {{{std::byte{0}}, 1}};
        spec.files = {{"f.bin", 0, 0, 1, 0x20}};
        auto reader = openBytes(buildCab(spec));
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Unsupported);
    }
}

TEST_CASE("cab reader rejects multi-cabinet sets and spanned files") {
    {
        TestCab spec;
        spec.flags = 0x0002;
        spec.nextLabels = {"disk2.cab", "Disk 2"};
        spec.folders[0].blocks = {{{std::byte{'p'}}, 1}};
        spec.files = {{"split.bin", 0, 0, 1, 0x20}};
        auto reader = openBytes(buildCab(spec));
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Unsupported);
    }
    {
        TestCab spec;
        spec.folders[0].blocks = {{{std::byte{'p'}}, 1}};
        spec.files = {{"s.bin", 0xFFFE, 0, 100, 0x20}};
        auto reader = openBytes(buildCab(spec));
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Unsupported);
    }
}

TEST_CASE("cab reader rejects files past their folder") {
    TestCab spec;
    spec.folders[0].blocks = {{{std::byte{'q'}}, 1}};
    spec.files = {{"f.txt", 0, 0, 2, 0x20}};
    auto reader = openBytes(buildCab(spec));
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("cab reader rejects overlapping data and bad checksums") {
    {
        TestCab spec;
        TestFolder first;
        first.blocks = {{{std::byte{'a'}}, 1}};
        TestFolder second;
        second.blocks = {{{std::byte{'b'}}, 1}};
        spec.folders = {first, second};
        spec.files = {{"f.txt", 0, 0, 1, 0x20}};
        Bytes bytes = buildCab(spec);
        // Patch the second folder's start back over the first folder's data.
        std::size_t folderBase = 36;
        for (int shift = 0; shift < 32; shift += 8) {
            bytes[folderBase + 8 + static_cast<std::size_t>(shift) / 8] =
                bytes[folderBase + static_cast<std::size_t>(shift) / 8];
        }
        auto reader = openBytes(bytes);
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Malformed);
    }
    {
        TestCab spec;
        spec.folders[0].blocks = {
            {Bytes{std::byte{'a'}}, std::uint64_t{1}, std::uint32_t{0x12345678}, false}
        };
        spec.files = {{"f.txt", 0, 0, 1, 0x20}};
        auto reader = openBytes(buildCab(spec));
        REQUIRE(reader);
        std::vector<std::byte> scratch(64);
        auto streamed =
            reader->streamEntry(reader->entries()[0], scratch, [&](std::span<const std::byte>) {
                return Result<void>{};
            });
        CHECK_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::Integrity);
    }
}

TEST_CASE("cab reader skips reserve areas") {
    TestCab spec;
    spec.flags = 0x0004;
    spec.cabinetReserve = {std::byte{0x11}, std::byte{0x22}};
    spec.folders[0].folderReserve = 3;
    spec.folders[0].dataReserve = 2;
    spec.folders[0].blocks = {{{std::byte{'r'}}, 1}};
    spec.files = {{"f.txt", 0, 0, 1, 0x20}};
    auto reader = openBytes(buildCab(spec));
    REQUIRE(reader);
    auto data = collect(*reader, reader->entries()[0]);
    CHECK(data == Bytes{std::byte{'r'}});
}

TEST_CASE("cab reader rejects folders without data and bad LZX windows") {
    {
        TestCab spec;
        spec.folders[0].blocks.clear();
        spec.files = {{"f.txt", 0, 0, 0, 0x20}};
        auto reader = openBytes(buildCab(spec));
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Malformed);
    }
    {
        TestCab spec;
        spec.folders[0].method = 3;
        spec.folders[0].windowBits = 14;
        spec.folders[0].blocks = {{{std::byte{0}}, 1}};
        spec.files = {{"f.txt", 0, 0, 1, 0x20}};
        auto reader = openBytes(buildCab(spec));
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Unsupported);
    }
}

TEST_CASE("cab reader enforces entry limits") {
    TestCab spec;
    spec.folders[0].blocks = {{{std::byte{'a'}}, 1}};
    spec.files = {{"f.txt", 0, 0, 1, 0x20}};
    Bytes bytes = buildCab(spec);
    cab::Limits limits;
    limits.maxEntries = 0;
    auto reader = openBytes(bytes, limits);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::LimitExceeded);
}

}
