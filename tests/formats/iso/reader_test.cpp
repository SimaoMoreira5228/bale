#include "formats/iso/reader.hpp"

#include "formats/detect.hpp"
#include "formats/iso/iso_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::iso;
using bale::iso::test::FileSpec;
using bale::iso::test::IsoImage;
using bale::iso::test::IsoSpec;

namespace {

std::vector<std::byte> golden(std::string_view name) {
    std::filesystem::path path = std::filesystem::path(FORMAT_GOLDEN_DIR) / "iso" / "data" / name;
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

Result<Reader> openBytes(std::span<const std::byte> bytes, const Limits& limits = {}) {
    bale::test::TempFile archive(bytes);
    REQUIRE(archive.ok());
    auto file = archive.open();
    REQUIRE(file);
    return Reader::open(std::move(*file), limits);
}

Result<Reader> openImage(const IsoImage& image, const Limits& limits = {}) {
    return openBytes(image.bytes, limits);
}

std::string streamAll(Reader& reader, const Entry& entry, std::size_t scratchSize = 256) {
    std::vector<std::byte> scratch(scratchSize);
    std::string text;
    auto streamed = reader.streamEntry(entry, scratch, [&](std::span<const std::byte> chunk) {
        text.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    REQUIRE(streamed);
    return text;
}

const Entry* findEntry(const Reader& reader, std::string_view name) {
    for (const auto& entry : reader.entries()) {
        if (entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

}

TEST_CASE("iso reader lists the genisoimage Rock Ridge golden") {
    // NOTE: tests/formats/iso/data/rr_joliet.iso was written by
    // `genisoimage -R -J` from cdrtools 1.1.11 over three inputs
    // (hello.txt, sub/nested.txt, link.txt -> hello.txt) whose
    // filesystem mtimes were fixed to 1577934245 (2020-01-02 03:04:05 UTC)
    // with touch -d @1577934245.
    auto reader = openBytes(golden("rr_joliet.iso"));
    REQUIRE(reader);

    auto entries = std::vector<Entry>(reader->entries().begin(), reader->entries().end());
    REQUIRE(entries.size() == 4);
    CHECK(entries[0].name == "hello.txt");
    CHECK(entries[0].size == 10);
    CHECK(entries[0].mode == 0100644);
    CHECK(entries[0].mtimeSeconds == 1577934245);
    CHECK(entries[0].kind == EntryKind::Regular);
    CHECK(entries[1].name == "link.txt");
    CHECK(entries[1].kind == EntryKind::Symlink);
    CHECK(entries[1].linkTarget == "hello.txt");
    CHECK(entries[2].name == "sub");
    CHECK(entries[2].kind == EntryKind::Directory);
    CHECK(entries[2].mode == 040755);
    CHECK(entries[3].name == "sub/nested.txt");
    CHECK(entries[3].size == 15);
    CHECK(streamAll(*reader, entries[0]) == "hello iso\n");
    CHECK(streamAll(*reader, entries[3]) == "nested content\n");
}

TEST_CASE("iso reader lists the genisoimage El Torito golden") {
    // NOTE: tests/formats/iso/data/eltorito.iso was written by
    // `genisoimage -R -J -no-emul-boot -boot-load-size 4
    // -b boot/boot.img -c boot/boot.cat` from cdrtools 1.1.11; the boot
    // image holds 2048 bytes starting with BOOTDATA. Only the boot
    // catalog timestamp is build-time dependent, so it is not asserted.
    auto reader = openBytes(golden("eltorito.iso"));
    REQUIRE(reader);

    const Entry* image = findEntry(*reader, "[BOOT]/BootImage-1.img");
    REQUIRE(image != nullptr);
    CHECK(image->size == 2048);
    CHECK(image->kind == EntryKind::Regular);
    CHECK(streamAll(*reader, *image).starts_with("BOOTDATA"));

    const Entry* catalog = findEntry(*reader, "boot/boot.cat");
    REQUIRE(catalog != nullptr);
    CHECK(catalog->size == 2048);
    const Entry* boot = findEntry(*reader, "boot/boot.img");
    REQUIRE(boot != nullptr);
    CHECK(boot->size == 2048);
    CHECK(streamAll(*reader, *boot) == streamAll(*reader, *image));
}

TEST_CASE("iso reader exposes plain names without Rock Ridge") {
    IsoSpec spec;
    FileSpec protocol;
    protocol.path = "docs/readme.txt";
    protocol.data = "plain\n";
    protocol.rockRidge = false;
    FileSpec trailing;
    trailing.path = "file";
    trailing.data = "x";
    trailing.rockRidge = false;
    FileSpec nested;
    nested.path = "docs/data.bin";
    nested.data = std::string("\0\x01\x02", 3);
    nested.rockRidge = false;
    spec.files = {protocol, trailing, nested};

    auto reader = openImage(iso::test::buildIso(spec));
    REQUIRE(reader);

    auto entries = std::vector<Entry>(reader->entries().begin(), reader->entries().end());
    REQUIRE(entries.size() == 4);
    CHECK(entries[0].name == "FILE");
    CHECK(streamAll(*reader, entries[0]) == "x");
    CHECK(entries[1].name == "DOCS");
    CHECK(entries[1].kind == EntryKind::Directory);
    CHECK(entries[1].mode == 040555);
    CHECK(entries[2].name == "DOCS/README.TXT");
    CHECK(entries[2].mode == 0100444);
    CHECK(streamAll(*reader, entries[2]) == "plain\n");
    CHECK(entries[3].name == "DOCS/DATA.BIN");
    CHECK(streamAll(*reader, entries[3], 1) == std::string("\0\x01\x02", 3));
}

TEST_CASE("iso reader prefers Rock Ridge names over Joliet") {
    IsoSpec spec;
    spec.joliet = true;
    FileSpec mixed;
    mixed.path = "MixedCase.txt";
    mixed.data = "rr\n";
    spec.files = {mixed};

    auto reader = openImage(iso::test::buildIso(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 1);
    CHECK(reader->entries()[0].name == "MixedCase.txt");

    IsoSpec plain;
    plain.joliet = true;
    FileSpec jolietOnly;
    jolietOnly.path = "lower.txt";
    jolietOnly.data = "joliet\n";
    jolietOnly.rockRidge = false;
    plain.files = {jolietOnly};

    auto fallback = openImage(iso::test::buildIso(plain));
    REQUIRE(fallback);
    REQUIRE(fallback->entries().size() == 1);
    CHECK(fallback->entries()[0].name == "lower.txt");
    CHECK(streamAll(*fallback, fallback->entries()[0]) == "joliet\n");
}

TEST_CASE("iso reader de-duplicates versioned files") {
    IsoSpec spec;
    FileSpec first;
    first.path = "note.txt";
    first.data = "first\n";
    first.rockRidge = false;
    first.version = ";1";
    FileSpec second;
    second.path = "note.txt";
    second.data = "second\n";
    second.rockRidge = false;
    second.version = ";2";
    spec.files = {first, second};

    // NOTE: versioned duplicates collapse onto one exposed name; the
    // first record wins and later versions are skipped.
    auto reader = openImage(iso::test::buildIso(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 1);
    CHECK(reader->entries()[0].name == "NOTE.TXT");
    CHECK(streamAll(*reader, reader->entries()[0]) == "first\n");
}

TEST_CASE("iso reader concatenates multi-extent files") {
    IsoSpec spec;
    FileSpec split;
    split.path = "big.bin";
    split.data = std::string(5000, 'z');
    split.extents = 2;
    spec.files = {split};

    auto reader = openImage(iso::test::buildIso(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 1);
    CHECK(reader->entries()[0].size == 5000);
    CHECK(streamAll(*reader, reader->entries()[0], 7) == std::string(5000, 'z'));
}

TEST_CASE("iso reader follows continuation areas past unknown entries") {
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

    auto reader = openImage(iso::test::buildIso(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 1);
    CHECK(reader->entries()[0].name == "ce.txt");
    CHECK(reader->entries()[0].mode == 0100644);
    CHECK(reader->entries()[0].mtimeSeconds == 1700000000);
    CHECK(streamAll(*reader, reader->entries()[0]) == "continued\n");
}

TEST_CASE("iso reader decodes long-form Rock Ridge timestamps") {
    IsoSpec spec;
    FileSpec file;
    file.path = "when.txt";
    file.data = "t\n";
    file.longStamp = true;
    spec.files = {file};

    auto reader = openImage(iso::test::buildIso(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 1);
    CHECK(reader->entries()[0].mtimeSeconds == 1700000000);
}

TEST_CASE("iso reader exposes boot images as opaque files") {
    IsoSpec spec;
    spec.boot = true;
    spec.bootData = "image-bytes";
    spec.files = {};

    auto reader = openImage(iso::test::buildIso(spec));
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 1);
    CHECK(reader->entries()[0].name == "[BOOT]/BootImage-1.img");
    CHECK(reader->entries()[0].size == 512);
    std::string padded("image-bytes");
    padded.append(512 - padded.size(), '\0');
    CHECK(streamAll(*reader, reader->entries()[0]) == padded);
}

TEST_CASE("iso reader streams data in bounded chunks") {
    IsoSpec spec;
    FileSpec file;
    file.path = "stream.bin";
    file.data = std::string(10'000, 'q');
    spec.files = {file};

    auto reader = openImage(iso::test::buildIso(spec));
    REQUIRE(reader);
    CHECK(streamAll(*reader, reader->entries()[0], 7) == std::string(10'000, 'q'));
}

TEST_CASE("iso reader rejects entry data past end of file") {
    IsoSpec spec;
    FileSpec file;
    file.path = "cut.bin";
    file.data = std::string(3000, 'c');
    spec.files = {file};
    IsoImage image = iso::test::buildIso(spec);

    auto reader = openImage(image);
    REQUIRE(reader);
    REQUIRE(reader->entries().size() == 1);

    image.bytes.resize(image.bytes.size() - 1097);
    auto truncated = openBytes(image.bytes);
    REQUIRE_FALSE(truncated);
    CHECK(truncated.error().kind == ErrorKind::Truncated);
}

TEST_CASE("looksLikeIso detects the primary descriptor") {
    std::array<std::byte, 7> probe{
        std::byte{1},
        std::byte{'C'},
        std::byte{'D'},
        std::byte{'0'},
        std::byte{'0'},
        std::byte{'1'},
        std::byte{1},
    };
    CHECK(looksLikePrimaryDescriptor(probe));
    probe[0] = std::byte{2};
    CHECK_FALSE(looksLikePrimaryDescriptor(probe));
    CHECK_FALSE(looksLikePrimaryDescriptor(std::span(probe).first(3)));

    bale::test::TempFile archive(golden("rr_joliet.iso"));
    auto file = archive.open();
    REQUIRE(file);
    auto format = detectFormat(*file);
    REQUIRE(format);
    CHECK(*format == ArchiveFormat{.container = Container::Iso});
    CHECK(name(*format) == "iso");
}
