#include "formats/wim/lzx.hpp"
#include "formats/wim/reader.hpp"

#include "formats/wim/lzx_vectors.hpp"
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

constexpr std::uint32_t flagLzx = 0x00040002;
constexpr std::uint32_t chunk32k = 32768;
constexpr std::uint32_t chunk64k = 65536;

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

std::vector<std::byte> asBytes(auto const& array) {
    return std::vector<std::byte>(array.begin(), array.end());
}

std::vector<std::byte> strBytes(std::string_view text) {
    std::vector<std::byte> out;
    out.reserve(text.size());
    for (char unit : text) {
        out.push_back(static_cast<std::byte>(unit));
    }
    return out;
}

std::vector<std::byte> formula(std::size_t length) {
    std::vector<std::byte> out(length);
    for (std::size_t index = 0; index < length; ++index) {
        out[index] = static_cast<std::byte>((index * 31 + 7) % 251);
    }
    return out;
}

void stamp(std::vector<std::byte>& data, std::size_t at, std::span<const std::byte> payload) {
    REQUIRE(at + payload.size() <= data.size());
    std::copy(payload.begin(), payload.end(), data.begin() + static_cast<std::ptrdiff_t>(at));
}

std::vector<std::byte> e8call(std::int32_t disp) {
    std::vector<std::byte>
        out{std::byte{0xE8}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};
    out[1] = static_cast<std::byte>(disp & 0xFF);
    out[2] = static_cast<std::byte>((disp >> 8) & 0xFF);
    out[3] = static_cast<std::byte>((disp >> 16) & 0xFF);
    out[4] = static_cast<std::byte>((disp >> 24) & 0xFF);
    return out;
}

std::vector<std::byte> fillPattern() {
    return strBytes("0123456789ABCDEF");
}

// NOTE: hermetic LZX bodies ride the test builder: the plain bytes become a
// file, the stored chunks become its compressed resource. Ground truth for
// the framing is the wimlib goldens below, not these vectors.
wim::test::TestWim lzxSpec(
    std::string name,
    const std::vector<std::byte>& plain,
    const std::vector<std::vector<std::byte>>& stored,
    std::uint32_t chunkSize = chunk32k
) {
    using namespace wim::test;
    TestWim spec;
    spec.flags = flagLzx;
    spec.chunkSize = chunkSize;
    TestFile file;
    file.path = std::move(name);
    file.data = plain;
    spec.images[0].files.push_back(file);
    spec.lzxBlobs.emplace_back(plain, stored);
    return spec;
}

Result<wim::Reader> openLzx(
    std::string name,
    const std::vector<std::byte>& plain,
    const std::vector<std::vector<std::byte>>& stored,
    std::uint32_t chunkSize = chunk32k
) {
    auto spec = lzxSpec(std::move(name), plain, stored, chunkSize);
    auto bytes = buildWim(spec);
    TempFile temp{std::span<const std::byte>(bytes)};
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    return wim::Reader::open(std::move(*file), {}, 0);
}

}

TEST_CASE("wim LZX decodes the reference goldens") {
    SUBCASE("wimlib LZX golden") {
        // NOTE: wl_lzx.wim was captured with wimlib-imagex 1.14.5
        // (--compress=lzx); only its metadata resource is LZX-compressed, which
        // is exactly the refusal this workstream lifts.
        auto reader = openBytes(golden("wl_lzx.wim"));
        REQUIRE(reader);
        REQUIRE(reader->entryCount() == 4);
        const wim::Entry* alpha = find(*reader, "a.txt");
        REQUIRE(alpha != nullptr);
        auto data = collect(*reader, *alpha);
        CHECK(std::string(reinterpret_cast<const char*>(data.data()), data.size()) == "alpha\n");
        const wim::Entry* hard = find(*reader, "hard.txt");
        REQUIRE(hard != nullptr);
        CHECK(hard->kind == wim::EntryKind::HardLink);
        CHECK(hard->linkTarget == "a.txt");
        const wim::Entry* soft = find(*reader, "soft.lnk");
        REQUIRE(soft != nullptr);
        CHECK(soft->kind == wim::EntryKind::Symlink);
        CHECK(soft->linkTarget == "b.txt");
    }

    SUBCASE("7-Zip multi-chunk golden") {
        // NOTE: lzx_multi.wim was captured with wimlib-imagex 1.14.5
        // (--compress=lzx) from a tree with a 100 KiB file (four LZX chunks),
        // an x86 binary (E8-heavy), links and an empty file. Hashes below are
        // the 7-Zip 26.04 extraction of the same file.
        auto reader = openBytes(golden("lzx_multi.wim"));
        REQUIRE(reader);
        REQUIRE(reader->entryCount() == 8);
        CHECK(collect(*reader, *find(*reader, "hello.txt")) == strBytes("hello wim lzx\n"));
        CHECK(fnv(collect(*reader, *find(*reader, "big.bin"))) == 0x5C798FAE363ABB4BULL);
        CHECK(fnv(collect(*reader, *find(*reader, "prog"))) == 0x097057C41E8D5F33ULL);
        CHECK(find(*reader, "empty.txt")->size == 0);
        CHECK(find(*reader, "hard.txt")->linkTarget == "a.txt");
    }

    SUBCASE("solid golden") {
        // NOTE: lzx_solid.wim was captured with wimlib-imagex 1.14.5
        // (--compress=lzx --solid --solid-compress=LZX): the same tree packed
        // into one solid LZX resource. Same hashes as the non-solid golden.
        auto reader = openBytes(golden("lzx_solid.wim"));
        REQUIRE(reader);
        REQUIRE(reader->entryCount() == 8);
        CHECK(fnv(collect(*reader, *find(*reader, "big.bin"))) == 0x5C798FAE363ABB4BULL);
        CHECK(fnv(collect(*reader, *find(*reader, "prog"))) == 0x097057C41E8D5F33ULL);
        CHECK(collect(*reader, *find(*reader, "hello.txt")) == strBytes("hello wim lzx\n"));
    }

    SUBCASE("64 KiB-chunk golden") {
        // NOTE: lzx_chunk64.wim was captured with wimlib-imagex 1.14.5
        // (--compress=lzx --chunk-size=64K): 24-bit block sizes, 32 slots, no
        // 32 KiB frame padding, per-chunk E8. Same tree and hashes again.
        auto reader = openBytes(golden("lzx_chunk64.wim"));
        REQUIRE(reader);
        REQUIRE(reader->entryCount() == 8);
        CHECK(fnv(collect(*reader, *find(*reader, "big.bin"))) == 0x5C798FAE363ABB4BULL);
        CHECK(fnv(collect(*reader, *find(*reader, "prog"))) == 0x097057C41E8D5F33ULL);
    }
}

TEST_CASE("wim LZX decodes a mid-chunk raw block with E8 and an odd pad") {
    // NOTE: a lone raw block never satisfies the chunk size rule, so the
    // E8-carrying odd-length raw block rides second in a full chunk.
    std::string para = "The quick brown fox jumps over the lazy dog. 0123456789\n";
    std::vector<std::byte> head;
    for (std::size_t index = 0; index < 584; ++index) {
        auto text = std::span(reinterpret_cast<const std::byte*>(para.data()), para.size());
        head.insert(head.end(), text.begin(), text.end());
    }
    auto tailFill = std::span(reinterpret_cast<const std::byte*>("0123456789ABCDEFGHJ"), 19);
    head.insert(head.end(), tailFill.begin(), tailFill.end());
    REQUIRE(head.size() == std::size_t{32768} - 45);
    for (std::size_t at : {std::size_t{1000}, std::size_t{20000}}) {
        stamp(head, at, e8call(-static_cast<std::int32_t>(at % std::size_t{251})));
    }
    std::vector<std::byte> tail = strBytes("header-0123456789");
    auto call = e8call(-8);
    tail.insert(tail.end(), call.begin(), call.end());
    auto tailText = strBytes("tail-pad-0123456789");
    tail.insert(tail.end(), tailText.begin(), tailText.end());
    tail.push_back(std::byte{0x00});
    auto tailEnd = strBytes("abc");
    tail.insert(tail.end(), tailEnd.begin(), tailEnd.end());
    REQUIRE(tail.size() == std::size_t{45});
    std::vector<std::byte> plain = head;
    plain.insert(plain.end(), tail.begin(), tail.end());
    auto stored = std::vector<std::vector<std::byte>>{asBytes(wim::test::kLzxraw_mid_chunk_c0)};
    auto reader = openLzx("v.bin", plain, stored);
    REQUIRE(reader);
    REQUIRE(reader->entryCount() == 1);
    CHECK(collect(*reader, reader->entries()[0]) == plain);
}

TEST_CASE("wim LZX decodes a mid-stream split across coded chunks") {
    std::string para = "The quick brown fox jumps over the lazy dog. 0123456789\n";
    std::vector<std::byte> head;
    for (std::size_t index = 0; index < 585; ++index) {
        auto text = std::span(reinterpret_cast<const std::byte*>(para.data()), para.size());
        head.insert(head.end(), text.begin(), text.end());
    }
    auto filler = std::span(reinterpret_cast<const std::byte*>("01234567"), 8);
    head.insert(head.end(), filler.begin(), filler.end());
    REQUIRE(head.size() == std::size_t{32768});
    for (std::size_t at :
         {std::size_t{1000}, std::size_t{20000}, std::size_t{30000}, std::size_t{32700}}) {
        stamp(head, at, e8call(-static_cast<std::int32_t>(at % std::size_t{251})));
    }
    stamp(head, chunk32k - 16, fillPattern());
    std::vector<std::byte> tail;
    for (std::size_t index = 0; index < 4; ++index) {
        auto text = std::span(reinterpret_cast<const std::byte*>(para.data()), para.size());
        tail.insert(tail.end(), text.begin(), text.end());
    }
    auto tailFill = std::span(reinterpret_cast<const std::byte*>("0123456789ABCDEF"), 16);
    tail.insert(tail.end(), tailFill.begin(), tailFill.end());
    REQUIRE(tail.size() == std::size_t{240});
    stamp(tail, 40, e8call(-7));
    std::vector<std::byte> plain = head;
    plain.insert(plain.end(), tail.begin(), tail.end());
    CHECK(plain.size() == std::size_t{32768} + 240);
    auto stored = std::vector<std::vector<std::byte>>{
        asBytes(wim::test::kLzxcoded_split_c0),
        asBytes(wim::test::kLzxcoded_split_c1),
    };
    auto reader = openLzx("v.bin", plain, stored);
    REQUIRE(reader);
    CHECK(collect(*reader, reader->entries()[0]) == plain);
}

TEST_CASE("wim LZX decodes a small verbatim block") {
    auto plain = asBytes(wim::test::kLzxverbatim_small_plain);
    auto stored = std::vector<std::vector<std::byte>>{asBytes(wim::test::kLzxverbatim_small_c0)};
    auto reader = openLzx("v.bin", plain, stored);
    REQUIRE(reader);
    CHECK(collect(*reader, reader->entries()[0]) == plain);
}

TEST_CASE("wim LZX decodes mixed raw, verbatim and aligned blocks") {
    std::vector<std::byte> raw = formula(120);
    std::string lorem = "lorem ipsum dolor sit amet ";
    std::vector<std::byte> near;
    for (std::size_t index = 0; index < 24; ++index) {
        auto text = std::span(reinterpret_cast<const std::byte*>(lorem.data()), lorem.size());
        near.insert(near.end(), text.begin(), text.end());
    }
    REQUIRE(near.size() == std::size_t{648});
    std::vector<std::byte> far = formula(4000);
    auto first = std::span<const std::byte>(near.data(), 400);
    for (std::size_t at : {std::size_t{1200}, std::size_t{2400}, std::size_t{3600}}) {
        stamp(far, at, first);
    }
    stamp(far, far.size() - 16, fillPattern());
    std::vector<std::byte> plain = raw;
    plain.insert(plain.end(), near.begin(), near.end());
    plain.insert(plain.end(), far.begin(), far.end());
    REQUIRE(plain.size() == std::size_t{4768});
    auto stored = std::vector<std::vector<std::byte>>{asBytes(wim::test::kLzxmixed_blocks_c0)};
    auto reader = openLzx("v.bin", plain, stored);
    REQUIRE(reader);
    CHECK(collect(*reader, reader->entries()[0]) == plain);
}

TEST_CASE("wim LZX decodes a 64 KiB chunk with a block crossing 32 KiB") {
    // NOTE: one 50000-byte aligned block in a 64 KiB chunk: the decoder
    // must not swallow alignment padding where CAB would have some.
    std::vector<std::byte> plain = formula(50000);
    auto first = std::span<const std::byte>(plain.data(), 1000);
    std::vector<std::byte> head(first.begin(), first.end());
    for (std::size_t at :
         {std::size_t{5000},
          std::size_t{10000},
          std::size_t{15000},
          std::size_t{20000},
          std::size_t{25000},
          std::size_t{30000},
          std::size_t{35000}}) {
        stamp(plain, at, head);
    }
    for (std::size_t at : {std::size_t{1000}, std::size_t{20000}, std::size_t{40000}}) {
        stamp(plain, at, e8call(-static_cast<std::int32_t>(at % std::size_t{251})));
    }
    stamp(plain, plain.size() - 16, fillPattern());
    auto stored = std::vector<std::vector<std::byte>>{asBytes(wim::test::kLzxaligned_cross64k_c0)};
    auto reader = openLzx("v.bin", plain, stored, chunk64k);
    REQUIRE(reader);
    CHECK(collect(*reader, reader->entries()[0]) == plain);
}

TEST_CASE("wim LZX applies E8 edge by edge") {
    // NOTE: the edge payload from the generator rides second in a full
    // chunk for the lone-raw-block rule above.
    std::string para = "The quick brown fox jumps over the lazy dog. 0123456789\n";
    std::vector<std::byte> head;
    for (std::size_t index = 0; index < 582; ++index) {
        auto text = std::span(reinterpret_cast<const std::byte*>(para.data()), para.size());
        head.insert(head.end(), text.begin(), text.end());
    }
    auto headFill = std::span(reinterpret_cast<const std::byte*>("0123456789ABCDEFGHI"), 19);
    head.insert(head.end(), headFill.begin(), headFill.end());
    REQUIRE(head.size() == std::size_t{32768} - 157);
    std::vector<std::vector<std::byte>> parts{
        e8call(0),
        strBytes("ab"),
        e8call(11999999),
        strBytes("cd"),
        e8call(12000000 - 40),
        strBytes("ef"),
        std::vector<std::byte>{
            std::byte{0xE8},
            std::byte{0x00},
            std::byte{0x1B},
            std::byte{0xB7},
            std::byte{0x00}
        },
        strBytes("gh"),
        std::vector<std::byte>{
            std::byte{0xE8},
            std::byte{0xFF},
            std::byte{0xFF},
            std::byte{0xFF},
            std::byte{0x7F}
        },
        strBytes("ij0123456789 tail!"),
    };
    std::vector<std::byte> tail = parts[0];
    for (std::size_t index = 1; index < parts.size(); ++index) {
        tail.push_back(std::byte{'.'});
        tail.insert(tail.end(), parts[index].begin(), parts[index].end());
    }
    auto last = std::vector<std::byte>{
        std::byte{0xE8},
        std::byte{0x01},
        std::byte{0x02},
        std::byte{0x03},
        std::byte{0x04}
    };
    tail.insert(tail.end(), last.begin(), last.end());
    while (tail.size() < 156 || tail.size() % 2 == 0) {
        tail.insert(tail.end() - 5, std::byte{'.'});
    }
    REQUIRE(tail.size() == std::size_t{157});
    std::vector<std::byte> plain = head;
    plain.insert(plain.end(), tail.begin(), tail.end());
    auto stored = std::vector<std::vector<std::byte>>{asBytes(wim::test::kLzxe8_edges_c0)};
    auto reader = openLzx("v.bin", plain, stored);
    REQUIRE(reader);
    CHECK(collect(*reader, reader->entries()[0]) == plain);
}

TEST_CASE("wim LZX maps chunk sizes to windows") {
    CHECK(*wim::windowBitsForChunk(32768, 0) == 15);
    CHECK(*wim::windowBitsForChunk(65536, 0) == 16);
    CHECK(*wim::windowBitsForChunk(2097152, 0) == 21);
    CHECK_FALSE(wim::windowBitsForChunk(4096, 0));
    CHECK_FALSE(wim::windowBitsForChunk(1ULL << 22, 0));
    CHECK_FALSE(wim::windowBitsForChunk(40000, 0));
    CHECK_FALSE(wim::windowBitsForChunk(0, 0));
}

TEST_CASE("wim LZX undoes E8 per chunk") {
    // NOTE: base zero, filesize 12000000, last 10 bytes untouched.
    std::vector<std::byte> chunk{
        std::byte{0xE8}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xE8}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
        std::byte{0xE8}, std::byte{0x00}, std::byte{0x1B}, std::byte{0xB7}, std::byte{0x00},
        std::byte{0xE8}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0x7F},
        std::byte{'p'},  std::byte{'a'},  std::byte{'d'},  std::byte{0xE8}, std::byte{0x01},
        std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{'!'},  std::byte{'!'},
    };
    wim::undoE8Chunk(chunk);
    std::vector<std::byte> expected{
        std::byte{0xE8}, std::byte{0x08}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
        std::byte{0xE8}, std::byte{0xFF}, std::byte{0x1A}, std::byte{0xB7}, std::byte{0x00},
        std::byte{0xE8}, std::byte{0x00}, std::byte{0x1B}, std::byte{0xB7}, std::byte{0x00},
        std::byte{0xE8}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}, std::byte{0x7F},
        std::byte{'p'},  std::byte{'a'},  std::byte{'d'},  std::byte{0xE8}, std::byte{0x01},
        std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{'!'},  std::byte{'!'},
    };
    CHECK(chunk == expected);
    std::vector<std::byte> tiny{std::byte{0xE8}, std::byte{0x01}};
    wim::undoE8Chunk(tiny);
    CHECK(tiny == std::vector<std::byte>{std::byte{0xE8}, std::byte{0x01}});
}

TEST_CASE("wim LZX refuses malformed chunks") {
    SUBCASE("a bad block type") {
        auto stored = asBytes(wim::test::kLzxverbatim_small_c0);
        stored[1] = static_cast<std::byte>(std::to_integer<unsigned>(stored[1]) & 0x1F);
        auto reader = openLzx("v.bin", asBytes(wim::test::kLzxverbatim_small_plain), {stored});
        REQUIRE(reader);
        std::vector<std::byte> scratch(64);
        auto streamed =
            reader->streamEntry(reader->entries()[0], scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::Malformed);
    }
    SUBCASE("a zero-size block") {
        // NOTE: verbatim type, explicit zero size: the first 20 bits carry the
        // whole header, so bytes 0..3 pin the rejection deterministically.
        auto stored = asBytes(wim::test::kLzxverbatim_small_c0);
        stored[0] = std::byte{0x20};
        stored[1] = std::byte{0x00};
        stored[2] = std::byte{0x00};
        stored[3] = std::byte{0x00};
        auto reader = openLzx("v.bin", asBytes(wim::test::kLzxverbatim_small_plain), {stored});
        REQUIRE(reader);
        std::vector<std::byte> scratch(64);
        auto streamed =
            reader->streamEntry(reader->entries()[0], scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::Malformed);
    }
    SUBCASE("a block past its chunk") {
        auto stored = asBytes(wim::test::kLzxverbatim_small_c0);
        stored[0] = std::byte{0x27};
        stored[1] = std::byte{0xFF};
        stored[2] = std::byte{0xFF};
        stored[3] = std::byte{0x00};
        auto reader = openLzx("v.bin", asBytes(wim::test::kLzxverbatim_small_plain), {stored});
        REQUIRE(reader);
        std::vector<std::byte> scratch(64);
        auto streamed =
            reader->streamEntry(reader->entries()[0], scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::Malformed);
    }
    SUBCASE("a damaged Huffman stream") {
        auto stored = asBytes(wim::test::kLzxverbatim_small_c0);
        stored[stored.size() / 2] =
            static_cast<std::byte>(std::to_integer<unsigned>(stored[stored.size() / 2]) ^ 0xFF);
        auto reader = openLzx("v.bin", asBytes(wim::test::kLzxverbatim_small_plain), {stored});
        REQUIRE(reader);
        std::vector<std::byte> scratch(64);
        auto streamed =
            reader->streamEntry(reader->entries()[0], scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::Malformed);
    }
    SUBCASE("a chunk that ends early") {
        auto stored = asBytes(wim::test::kLzxverbatim_small_c0);
        stored.resize(stored.size() - 10);
        auto reader = openLzx("v.bin", asBytes(wim::test::kLzxverbatim_small_plain), {stored});
        REQUIRE(reader);
        std::vector<std::byte> scratch(64);
        auto streamed =
            reader->streamEntry(reader->entries()[0], scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::Malformed);
    }
    SUBCASE("truncation past the file end") {
        TempFile temp{std::span<const std::byte>(wim::test::kLzxverbatim_small_c0)};
        REQUIRE(temp.ok());
        auto file = temp.open();
        REQUIRE(file);
        auto decoded = wim::decodeLzxChunk(*file, 0, 200, 263, chunk32k, 0);
        REQUIRE_FALSE(decoded);
        CHECK(decoded.error().kind == ErrorKind::Truncated);
    }
    SUBCASE("a ragged chunk size") {
        // NOTE: header-level budget pin: compressed archives need a power of
        // two chunk size, so decode never sees unbounded windows.
        wim::test::TestWim spec;
        spec.flags = flagLzx;
        spec.chunkSize = 40000;
        wim::test::TestFile file;
        file.path = "z.bin";
        file.data = {std::byte{'z'}};
        spec.images[0].files.push_back(file);
        auto bytes = buildWim(spec);
        auto reader = openBytes(bytes);
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Malformed);
    }
    SUBCASE("an oversized chunk window") {
        auto plain = std::vector<std::byte>(100, std::byte{'x'});
        auto stored = std::vector<std::vector<std::byte>>{std::vector<std::byte>(50, std::byte{0})};
        auto spec = lzxSpec("v.bin", plain, stored, 1U << 22);
        auto bytes = buildWim(spec);
        auto reader = openBytes(bytes);
        REQUIRE(reader);
        std::vector<std::byte> scratch(64);
        auto streamed =
            reader->streamEntry(reader->entries()[0], scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
        REQUIRE_FALSE(streamed);
        CHECK(streamed.error().kind == ErrorKind::Unsupported);
    }
}
