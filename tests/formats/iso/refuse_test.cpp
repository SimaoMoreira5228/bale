#include "formats/iso/reader.hpp"

#include "formats/iso/iso_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::iso;
using bale::iso::test::FileSpec;
using bale::iso::test::IsoImage;
using bale::iso::test::IsoSpec;

namespace {

constexpr std::size_t sectorBytes = 2048;

ErrorKind openKind(std::span<const std::byte> bytes, const Limits& limits = {}) {
    bale::test::TempFile archive(bytes);
    REQUIRE(archive.ok());
    auto file = archive.open();
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file), limits);
    if (!reader) {
        return reader.error().kind;
    }
    return ErrorKind::Io;
}

ErrorKind openKindImage(const IsoImage& image, const Limits& limits = {}) {
    return openKind(image.bytes, limits);
}

void patch(std::vector<std::byte>& bytes, std::size_t at, std::byte value) {
    REQUIRE(at < bytes.size());
    bytes[at] = value;
}

void patchId(std::vector<std::byte>& bytes, std::size_t at, std::string_view text) {
    REQUIRE(at + text.size() <= bytes.size());
    for (std::size_t index = 0; index < text.size(); ++index) {
        bytes[at + index] = static_cast<std::byte>(text[index]);
    }
}

IsoImage basic() {
    IsoSpec spec;
    FileSpec file;
    file.path = "hello.txt";
    file.data = "hello\n";
    spec.files = {file};
    return iso::test::buildIso(spec);
}

void patchBoth32(std::vector<std::byte>& bytes, std::size_t at, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        bytes[at + static_cast<std::size_t>(shift) / 8] =
            static_cast<std::byte>((value >> shift) & 0xFF);
    }
    for (int shift = 24; shift >= 0; shift -= 8) {
        bytes[at + 4 + static_cast<std::size_t>(24 - shift) / 8] =
            static_cast<std::byte>((value >> shift) & 0xFF);
    }
}

}

TEST_CASE("iso reader rejects structurally invalid images") {
    SUBCASE("non-images") {
        CHECK(openKind({}) == ErrorKind::Malformed);
        std::vector<std::byte> tiny(4, std::byte{0});
        CHECK(openKind(tiny) == ErrorKind::Malformed);

        IsoImage image = basic();
        patchId(image.bytes, 16 * sectorBytes + 1, "CD002");
        CHECK(openKindImage(image) == ErrorKind::Malformed);
    }
    SUBCASE("a descriptor terminator") {
        IsoSpec spec;
        spec.files = {};
        spec.noTerminator = true;
        CHECK(openKindImage(iso::test::buildIso(spec)) == ErrorKind::Malformed);

        IsoImage image = basic();
        patch(image.bytes, image.terminatorByte, std::byte{0});
        CHECK(openKindImage(image) == ErrorKind::Malformed);
    }
    SUBCASE("duplicate primary descriptors") {
        IsoSpec spec;
        spec.files = {};
        spec.duplicatePvd = true;
        CHECK(openKindImage(iso::test::buildIso(spec)) == ErrorKind::Malformed);
    }
    SUBCASE("non-2048-byte sectors") {
        IsoImage image = basic();
        std::size_t at = 16 * sectorBytes + 128;
        patch(image.bytes, at, std::byte{0});
        patch(image.bytes, at + 1, std::byte{4});
        patch(image.bytes, at + 2, std::byte{4});
        patch(image.bytes, at + 3, std::byte{0});
        CHECK(openKindImage(image) == ErrorKind::Unsupported);
    }
    SUBCASE("UDF bridges explicitly") {
        IsoImage image = basic();
        patchId(image.bytes, 17 * sectorBytes + 1, "BEA01");
        CHECK(openKindImage(image) == ErrorKind::Unsupported);

        IsoImage second = basic();
        patchId(second.bytes, 17 * sectorBytes + 1, "NSR03");
        CHECK(openKindImage(second) == ErrorKind::Unsupported);

        IsoSpec bridge;
        bridge.files = {};
        bridge.udfBridge = true;
        CHECK(openKindImage(iso::test::buildIso(bridge)) == ErrorKind::Unsupported);
    }
    SUBCASE("unknown volume descriptors") {
        IsoImage image = basic();
        patch(image.bytes, 17 * sectorBytes, std::byte{3});
        CHECK(openKindImage(image) == ErrorKind::Malformed);
    }
}
TEST_CASE("iso reader rejects out-of-bounds and malformed extents") {
    SUBCASE("root extents in the system area") {
        IsoImage image = basic();
        patchBoth32(image.bytes, 16 * sectorBytes + 156 + 2, 5);
        CHECK(openKindImage(image) == ErrorKind::Malformed);
    }
    SUBCASE("directories past end of file") {
        IsoImage image = basic();
        patchBoth32(image.bytes, 16 * sectorBytes + 156 + 10, 0x10000);
        CHECK(openKindImage(image) == ErrorKind::Truncated);
    }
    SUBCASE("path tables past end of file") {
        IsoImage image = basic();
        patchBoth32(image.bytes, 16 * sectorBytes + 132, 0x1000000);
        CHECK(openKindImage(image) == ErrorKind::Truncated);
    }
    SUBCASE("interleaved extents") {
        IsoImage image = basic();
        std::size_t record = image.records["hello.txt"];
        patch(image.bytes, record + 26, std::byte{1});
        CHECK(openKindImage(image) == ErrorKind::Unsupported);
    }
    SUBCASE("associated files") {
        IsoImage image = basic();
        std::size_t record = image.records["hello.txt"];
        patch(image.bytes, record + 25, std::byte{0x04});
        CHECK(openKindImage(image) == ErrorKind::Unsupported);
    }
    SUBCASE("multi-volume sets") {
        IsoImage image = basic();
        std::size_t record = image.records["hello.txt"];
        patch(image.bytes, record + 28, std::byte{2});
        patch(image.bytes, record + 29, std::byte{0});
        patch(image.bytes, record + 30, std::byte{0});
        patch(image.bytes, record + 31, std::byte{2});
        CHECK(openKindImage(image) == ErrorKind::Unsupported);
    }
    SUBCASE("extended attributes") {
        IsoImage image = basic();
        std::size_t record = image.records["hello.txt"];
        patch(image.bytes, record + 1, std::byte{1});
        CHECK(openKindImage(image) == ErrorKind::Unsupported);
    }
    SUBCASE("Rock Ridge relocation") {
        IsoSpec spec;
        FileSpec file;
        file.path = "reloc.txt";
        file.data = "x\n";
        file.systemExtra = std::string("CL\x0C\x01", 4) + std::string(8, '\0');
        spec.files = {file};
        CHECK(openKindImage(iso::test::buildIso(spec)) == ErrorKind::Unsupported);
    }
    SUBCASE("unterminated multi-extent entries") {
        IsoSpec spec;
        FileSpec file;
        file.path = "big.bin";
        file.data = std::string(3000, 'b');
        file.extents = 2;
        spec.files = {file};
        IsoImage image = iso::test::buildIso(spec);

        std::size_t first = image.records["big.bin"];
        std::size_t second =
            first + static_cast<std::size_t>(static_cast<unsigned char>(image.bytes[first]));
        patch(image.bytes, second + 33, std::byte{'x'});
        CHECK(openKindImage(image) == ErrorKind::Malformed);
    }
    SUBCASE("extents in the system area") {
        IsoSpec spec;
        FileSpec file;
        file.path = "early.txt";
        file.data = "x\n";
        file.extentLba = 5;
        spec.files = {file};
        CHECK(openKindImage(iso::test::buildIso(spec)) == ErrorKind::Malformed);
    }
    SUBCASE("continuations past end of file") {
        IsoSpec spec;
        FileSpec file;
        file.path = "ce.txt";
        file.data = "continued\n";
        std::string filler;
        for (int index = 0; index < 20; ++index) {
            filler += std::string("ZZ\x08\x01", 4) + std::string(4, static_cast<char>(index));
        }
        file.systemExtra = filler;
        spec.files = {file};
        IsoImage image = iso::test::buildIso(spec);
        REQUIRE(openKindImage(image) == ErrorKind::Io);

        image.bytes.resize(image.bytes.size() - 2048 + 100);
        CHECK(openKindImage(image) == ErrorKind::Truncated);
    }
    SUBCASE("truncation at every boundary") {
        IsoImage image = basic();
        const auto& full = image.bytes;
        for (std::size_t cut = 0; cut < full.size(); cut += 257) {
            CAPTURE(cut);
            auto prefix = std::vector<std::byte>(
                full.begin(),
                full.begin() + static_cast<std::ptrdiff_t>(cut)
            );
            auto kind = openKind(prefix);
            if (cut < 20 * sectorBytes) {
                CHECK(kind != ErrorKind::Io);
                CHECK((kind == ErrorKind::Malformed || kind == ErrorKind::Truncated));
            }
        }

        CHECK(openKind(full) == ErrorKind::Io);
        auto shaved = std::vector<std::byte>(full.begin(), full.end() - 1);
        CHECK(openKind(shaved) == ErrorKind::Io);
    }
}
TEST_CASE("iso reader rejects bad names, timestamps, catalogs and mappings") {
    SUBCASE("bad Joliet names") {
        IsoSpec spec;
        spec.joliet = true;
        FileSpec file;
        file.path = "lower.txt";
        file.data = "j\n";
        file.rockRidge = false;
        spec.files = {file};

        IsoImage image = iso::test::buildIso(spec);
        std::size_t record = image.jolietRootByte + 68;
        std::size_t nameLength = record + 32;
        std::size_t name = record + 33;
        IsoImage surrogate = image;
        patch(surrogate.bytes, name, std::byte{0xD8});
        patch(surrogate.bytes, name + 1, std::byte{0x00});
        CHECK(openKindImage(surrogate) == ErrorKind::Malformed);

        IsoImage odd = image;
        patch(odd.bytes, nameLength, std::byte{5});
        CHECK(openKindImage(odd) == ErrorKind::Malformed);
    }
    SUBCASE("bad Rock Ridge timestamps") {
        IsoImage image = basic();
        std::size_t record = image.records["hello.txt"];
        std::size_t recordEnd =
            record + static_cast<std::size_t>(static_cast<unsigned char>(image.bytes[record]));
        std::size_t offset = 0;
        bool found = false;
        for (std::size_t index = record; index + 1 < recordEnd; ++index) {
            if (image.bytes[index] == std::byte{'T'} && image.bytes[index + 1] == std::byte{'F'}) {
                offset = index;
                found = true;
                break;
            }
        }
        REQUIRE(found);
        patch(image.bytes, offset + 2, std::byte{12});
        CHECK(openKindImage(image) == ErrorKind::Malformed);
    }
    SUBCASE("the El Torito catalog") {
        IsoSpec spec;
        spec.boot = true;
        spec.bootData = "image-bytes";
        spec.files = {};

        IsoImage image = iso::test::buildIso(spec);
        REQUIRE(openKindImage(image) == ErrorKind::Io);

        IsoImage checksum = image;
        patch(checksum.bytes, checksum.catalogByte + 28, std::byte{0});
        CHECK(openKindImage(checksum) == ErrorKind::Malformed);

        IsoImage unknown = image;
        patch(unknown.bytes, unknown.catalogByte + 32, std::byte{7});
        CHECK(openKindImage(unknown) == ErrorKind::Malformed);

        IsoImage emulation = image;
        patch(emulation.bytes, emulation.catalogByte + 33, std::byte{4});
        CHECK(openKindImage(emulation) == ErrorKind::Unsupported);

        IsoImage truncated = image;
        truncated.bytes.resize(image.bootImageByte + 511);
        CHECK(openKindImage(truncated) == ErrorKind::Truncated);

        IsoImage doubled = image;
        std::copy(
            image.bytes.begin() + static_cast<std::ptrdiff_t>(17 * sectorBytes),
            image.bytes.begin() + static_cast<std::ptrdiff_t>(18 * sectorBytes),
            doubled.bytes.begin() + static_cast<std::ptrdiff_t>(18 * sectorBytes)
        );
        CHECK(openKindImage(doubled) == ErrorKind::Unsupported);
    }
    SUBCASE("emulation media to fixed image sizes") {
        IsoSpec spec;
        spec.boot = true;
        spec.bootData = std::string(std::size_t{1440} * 1024, 'F');
        spec.files = {};
        IsoImage image = iso::test::buildIso(spec);
        patch(image.bytes, image.catalogByte + 33, std::byte{2});

        bale::test::TempFile archive(image.bytes);
        REQUIRE(archive.ok());
        auto file = archive.open();
        REQUIRE(file);
        auto reader = Reader::open(std::move(*file));
        REQUIRE(reader);
        REQUIRE(reader->entries().size() == 1);
        CHECK(reader->entries()[0].size == std::size_t{1440} * 1024);
    }
}
TEST_CASE("iso reader enforces caller limits before allocating") {
    IsoImage image = basic();

    Limits entries;
    entries.maxEntries = 0;
    CHECK(openKindImage(image, entries) == ErrorKind::LimitExceeded);

    Limits sizes;
    sizes.maxEntryBytes = 1;
    CHECK(openKindImage(image, sizes) == ErrorKind::LimitExceeded);

    Limits total;
    total.maxTotalBytes = 1;
    CHECK(openKindImage(image, total) == ErrorKind::LimitExceeded);

    Limits directories;
    directories.maxDirectoryBytes = 1;
    CHECK(openKindImage(image, directories) == ErrorKind::LimitExceeded);

    Limits depth;
    depth.maxDepth = 0;
    CHECK(openKindImage(image, depth) == ErrorKind::LimitExceeded);

    Limits names;
    names.maxNameBytes = 1;
    CHECK(openKindImage(image, names) == ErrorKind::LimitExceeded);

    Limits tables;
    tables.maxPathTableBytes = 1;
    CHECK(openKindImage(image, tables) == ErrorKind::LimitExceeded);

    IsoSpec ce;
    FileSpec file;
    file.path = "ce.txt";
    file.data = "continued\n";
    std::string filler;
    for (int index = 0; index < 20; ++index) {
        filler += std::string("ZZ\x08\x01", 4) + std::string(4, static_cast<char>(index));
    }
    file.systemExtra = filler;
    ce.files = {file};
    IsoImage continued = iso::test::buildIso(ce);
    REQUIRE(openKindImage(continued) == ErrorKind::Io);

    Limits susp;
    susp.maxSuspBytes = 1;
    CHECK(openKindImage(continued, susp) == ErrorKind::LimitExceeded);

    Limits hops;
    hops.maxContinuationHops = 0;
    CHECK(openKindImage(continued, hops) == ErrorKind::LimitExceeded);
}
