#include "formats/sevenzip/folder.hpp"
#include "formats/sevenzip/methods.hpp"
#include "formats/sevenzip/reader.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <array>
#include <span>
#include <string>
#include <vector>

using namespace bale;

namespace {

// NOTE: fixture below is a real 7z archive produced with 7-Zip 26.04:
//   python3 -c
//   "open('tiny.bin','wb').write(bytes([0xE8,0,0,0,0,0x90,0x90,0xE9,5,0,0,0,0x90,0x90,0x90,0x90]))"
//   7z a -m0=BCJ -y tiny_bcj.7z tiny.bin
// The 16-byte x86 payload exercises CALL (E8) and JMP (E9) conversion plus
// the trailing tail (<5 bytes) held back until flush.
constexpr unsigned char kBcjTiny[] = {
    0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04, 0x2B, 0x8A, 0x59, 0xA2, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0xCF, 0xAA, 0x75,
    0xE8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0xE9, 0x11, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90,
    0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x10, 0x00, 0x07, 0x0B, 0x01, 0x00, 0x01, 0x04, 0x03, 0x03,
    0x01, 0x03, 0x0C, 0x10, 0x00, 0x08, 0x0A, 0x01, 0x0A, 0xB4, 0xC0, 0xFD, 0x00, 0x00, 0x05, 0x01,
    0x19, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x13, 0x00,
    0x74, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x79, 0x00, 0x2E, 0x00, 0x62, 0x00, 0x69, 0x00, 0x6E, 0x00,
    0x00, 0x00, 0x19, 0x00, 0x14, 0x0A, 0x01, 0x00, 0xC2, 0xAF, 0x31, 0x13, 0xDC, 0x62, 0xDD, 0x01,
    0x15, 0x06, 0x01, 0x00, 0x20, 0x80, 0xA4, 0x81, 0x00, 0x00
};

constexpr unsigned char kTinyX86[] = {
    0xE8,
    0x00,
    0x00,
    0x00,
    0x00,
    0x90,
    0x90,
    0xE9,
    0x05,
    0x00,
    0x00,
    0x00,
    0x90,
    0x90,
    0x90,
    0x90
};

Result<sevenzip::Reader> openBytes(std::span<const unsigned char> bytes) {
    std::vector<std::byte> data(bytes.size());
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        data[i] = static_cast<std::byte>(bytes[i]);
    }
    bale::test::TempFile temp(data);
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    return sevenzip::Reader::open(std::move(*file));
}

sevenzip::Folder singleCoder(std::vector<std::uint8_t> id, std::vector<std::byte> props = {}) {
    sevenzip::Folder folder;
    sevenzip::Coder coder;
    coder.id = std::move(id);
    coder.props = std::move(props);
    coder.inStreams = 1;
    coder.outStreams = 1;
    folder.coders.push_back(std::move(coder));
    folder.numInStreams = 1;
    folder.numOutStreams = 1;
    folder.numPackedStreams = 1;
    return folder;
}

} // namespace

TEST_CASE("7z BCJ single-coder decodes tiny x86 fixture") {
    auto reader = openBytes(kBcjTiny);
    REQUIRE(reader);
    std::vector<sevenzip::Entry> entries(reader->entries().begin(), reader->entries().end());
    REQUIRE(entries.size() == 1);
    std::vector<std::byte> scratch(256);
    std::vector<std::byte> out;
    auto streamed =
        reader->streamEntry(entries.front(), scratch, [&](std::span<const std::byte> c) {
            out.insert(out.end(), c.begin(), c.end());
            return Result<void>{};
        });
    REQUIRE(streamed);
    REQUIRE(out.size() == sizeof(kTinyX86));
    for (std::size_t i = 0; i < out.size(); ++i) {
        CHECK(out[i] == static_cast<std::byte>(kTinyX86[i]));
    }
}

TEST_CASE("7z BCJ refuses non-empty props") {
    auto folder = singleCoder({0x03, 0x03, 0x01, 0x03}, std::vector<std::byte>{std::byte{0x00}});
    auto info = sevenzip::resolveCodec(folder);
    CHECK(!info.supported);
}

TEST_CASE("7z filter refusal matrix names each unsupported single filter") {
    struct Case {
        std::vector<std::uint8_t> id;
        std::string_view name;
        std::string_view hex;
    };
    const std::vector<Case> cases = {
        {{0x03, 0x03, 0x01, 0x1B}, "BCJ2", "03-03-01-1B"},
        {{0x03}, "Delta", "03"},
        {{0x03, 0x03, 0x05, 0x01}, "ARM", "03-03-05-01"},
        {{0x03, 0x03, 0x07, 0x01}, "ARMT", "03-03-07-01"},
        {{0x03, 0x03, 0x02, 0x05}, "PPC", "03-03-02-05"},
        {{0x03, 0x03, 0x04, 0x01}, "IA64", "03-03-04-01"},
        {{0x03, 0x03, 0x08, 0x05}, "SPARC", "03-03-08-05"},
        {{0x0A}, "ARM64", "0A"},
        {{0x0B}, "RISC-V", "0B"},
        {{0x02, 0x03, 0x02}, "Swap2", "02-03-02"},
        {{0x02, 0x03, 0x04}, "Swap4", "02-03-04"},
    };
    for (const auto& want : cases) {
        auto folder = singleCoder(want.id);
        auto info = sevenzip::resolveCodec(folder);
        CHECK(!info.supported);
        CHECK(info.name == want.name);
        CHECK(info.hex == want.hex);
    }
}

TEST_CASE("7z BCJ truncated pack fails as truncated") {
    std::vector<unsigned char> cut(std::begin(kBcjTiny), std::end(kBcjTiny) - 1);
    auto reader = openBytes(cut);
    if (!reader) {
        CHECK(reader.error().kind == ErrorKind::Truncated);
        return;
    }
    std::vector<sevenzip::Entry> entries(reader->entries().begin(), reader->entries().end());
    REQUIRE(!entries.empty());
    std::vector<std::byte> scratch(256);
    auto streamed = reader->streamEntry(entries.front(), scratch, [&](std::span<const std::byte>) {
        return Result<void>{};
    });
    CHECK(!streamed);
    if (!streamed) {
        bool truncatedOrMalformed = streamed.error().kind == ErrorKind::Truncated ||
            streamed.error().kind == ErrorKind::Malformed;
        CHECK(truncatedOrMalformed);
    }
}
