#include "archive/chunk.hpp"
#include "archive/commit.hpp"
#include "archive/index.hpp"
#include "archive/manifest.hpp"

#include "archive/archive_fixture.hpp"

#include <doctest/doctest.h>

#include <cstdint>
#include <initializer_list>
#include <string_view>
#include <vector>

using namespace bale;
using namespace bale::archive;
using namespace std::literals;
using bale::test::bytesOf;
using bale::test::fromHex;
using bale::test::syntheticKey;

namespace {

// NOTE: every golden payload below was produced by an independent Python encoder written from
// the schema description, not by the C++ encoder under test.
std::vector<std::byte> goldenDataPayload() {
    return fromHex(
        "28 03 01 01 05 20 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 "
        "12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 07 01 05 68 65 6C 6C 6F"
    );
}

std::vector<std::byte> goldenIndex() {
    return fromHex(
        "03 01 01 05 33 01 31 03 01 01 05 20 00 01 02 03 04 05 06 07 08 09 0A 0B "
        "0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 07 01 05 09 "
        "01 40 0B 01 66 0D 01 00"
    );
}

std::vector<std::byte> goldenManifestBytes() {
    return fromHex(
        "03 01 01 05 76 04 0A 03 01 64 05 01 02 0C 02 ED 03 45 03 03 64 2F 66 05 "
        "01 01 07 01 05 09 2A 01 28 03 01 01 05 20 00 01 02 03 04 05 06 07 08 09 "
        "0A 0B 0C 0D 0E 0F 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 07 01 "
        "05 0A 08 FF FF FF FF FF FF FF FF 0C 02 A4 03 0D 03 03 64 2F 67 05 01 04 "
        "15 03 64 2F 66 15 03 01 6C 05 01 03 0A 08 01 00 00 00 00 00 00 00 13 03 "
        "64 2F 66 06 02 68 69 08 04 62 61 6C 65"
    );
}

std::vector<std::byte> goldenCommitBytes() {
    return fromHex(
        "03 01 01 05 01 01 07 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 09 01 00 0B 02 AC 02 0D "
        "01 78 0F 20 A0 A1 A2 A3 A4 A5 A6 A7 A8 A9 AA AB AC AD AE AF B0 B1 B2 B3 "
        "B4 B5 B6 B7 B8 B9 BA BB BC BD BE BF 11 02 A4 03 13 02 96 01 15 20 40 41 "
        "42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 "
        "5A 5B 5C 5D 5E 5F"
    );
}

Manifest goldenManifest() {
    Manifest manifest;
    manifest.chunks.push_back(syntheticKey(5));
    manifest.entries = {
        ManifestEntry{
            .path = "d",
            .mode = 0755,
            .kind = EntryKind::Directory,
        },
        ManifestEntry{
            .path = "d/f",
            .length = 5,
            .mtimeNanoseconds = -1,
            .mode = 0644,
            .firstChunk = 0,
            .chunkCount = 1,
            .kind = EntryKind::Regular,
        },
        ManifestEntry{
            .path = "d/g",
            .target = "d/f",
            .kind = EntryKind::HardLink,
        },
        ManifestEntry{
            .path = "l",
            .target = "d/f",
            .mtimeNanoseconds = 1,
            .kind = EntryKind::Symlink,
        },
    };
    manifest.comment = "hi";
    manifest.writer = "bale";
    return manifest;
}

Commit goldenCommit() {
    Commit commit;
    commit.manifest.offset = 300;
    commit.manifest.length = 120;
    commit.index.offset = 420;
    commit.index.length = 150;
    for (std::size_t index = 0; index < blake3DigestSize; ++index) {
        commit.manifest.digest[index] = static_cast<std::byte>(0xA0 + index);
        commit.index.digest[index] = static_cast<std::byte>(0x40 + index);
    }
    return commit;
}

struct RawField {
    std::uint32_t number = 0;
    Criticality criticality = Criticality::Critical;
    std::vector<std::byte> value;
};

std::vector<std::byte> uleb(std::uint64_t value) {
    std::vector<std::byte> out;
    appendLeb128(out, value);
    return out;
}

std::vector<std::byte> text(std::string_view value) {
    auto view = bytesOf(value);
    return {view.begin(), view.end()};
}

std::vector<std::byte> tlv(std::initializer_list<RawField> fields) {
    std::vector<std::byte> out;
    TlvWriter writer(out);
    for (const auto& field : fields) {
        REQUIRE(writer.bytes(field.number, field.criticality, field.value));
    }
    return out;
}

std::vector<std::byte> list(std::initializer_list<std::vector<std::byte>> elements) {
    std::vector<std::byte> out = uleb(elements.size());
    for (const auto& element : elements) {
        appendTlvListElement(out, element);
    }
    return out;
}

std::vector<std::byte> rawManifest(std::initializer_list<std::vector<std::byte>> entries) {
    return tlv({{1, Criticality::Critical, uleb(1)}, {2, Criticality::Critical, list(entries)}});
}

std::vector<std::byte> encodedManifest(const Manifest& manifest) {
    std::vector<std::byte> out;
    REQUIRE(encodeManifest(manifest, out));
    return out;
}

Result<void> decodeBytes(std::span<const std::byte> payload, const Limits& limits = {}) {
    Manifest manifest;
    return decodeManifest(payload, 0, limits, manifest);
}

ErrorKind manifestError(const Manifest& manifest) {
    auto decoded = decodeBytes(encodedManifest(manifest));
    REQUIRE_FALSE(decoded);
    return decoded.error().kind;
}

ErrorKind rawError(std::span<const std::byte> payload) {
    auto decoded = decodeBytes(payload);
    REQUIRE_FALSE(decoded);
    return decoded.error().kind;
}

ManifestEntry file(std::string_view path) {
    return ManifestEntry{
        .path = path,
        .kind = EntryKind::Regular,
    };
}

ManifestEntry directory(std::string_view path) {
    return ManifestEntry{
        .path = path,
        .kind = EntryKind::Directory,
    };
}

Manifest manifestOf(std::initializer_list<ManifestEntry> entries) {
    Manifest manifest;
    manifest.entries = entries;
    return manifest;
}

}

TEST_CASE("chunk identity is domain-separated BLAKE3 of the uncompressed bytes") {
    auto key = chunkKeyOf(bytesOf("hello"));
    CHECK(key.algorithm == HashAlgorithm::Blake3);
    CHECK(key.length == 5);
    CHECK(
        std::vector(key.digest.begin(), key.digest.end()) ==
        fromHex(
            "5F CC 12 22 12 22 F9 D8 0C B3 E5 1A 1A D8 A1 5D 63 79 DF 45 5C A2 CA 07 "
            "46 F3 C7 99 BB D0 7B 90"
        )
    );
}

TEST_CASE("DATA payload golden bytes: descriptor size, chunk key TLV, then chunk bytes") {
    auto golden = goldenDataPayload();
    std::vector<std::byte> descriptor;
    REQUIRE(encodeDataDescriptor(syntheticKey(5), descriptor));
    descriptor.insert(descriptor.end(), golden.end() - 5, golden.end());
    CHECK(descriptor == golden);

    auto decoded = decodeDataPayload(golden, 1000);
    REQUIRE(decoded);
    CHECK(decoded->key == syntheticKey(5));
    CHECK(decoded->descriptorSize == 41);
    CHECK(decoded->encoded.size() == 5);

    for (std::size_t size = 0; size < 41; ++size) {
        CAPTURE(size);
        CHECK_FALSE(decodeDataPayload(std::span(golden).first(size), 0));
    }
}

TEST_CASE("DATA descriptors with hostile keys or sizes are rejected precisely") {
    auto descriptorOf = [](std::initializer_list<RawField> fields) {
        auto key = tlv(fields);
        std::vector<std::byte> out = uleb(key.size());
        out.insert(out.end(), key.begin(), key.end());
        return out;
    };
    auto digest = std::vector<std::byte>(32, std::byte{7});
    auto decodeKind = [](const std::vector<std::byte>& payload) {
        auto decoded = decodeDataPayload(payload, 0);
        REQUIRE_FALSE(decoded);
        return decoded.error().kind;
    };

    CHECK(
        decodeKind(descriptorOf(
            {{1, Criticality::Critical, uleb(2)},
             {2, Criticality::Critical, digest},
             {3, Criticality::Critical, uleb(5)}}
        )) == ErrorKind::Unsupported
    );
    CHECK(
        decodeKind(descriptorOf(
            {{1, Criticality::Critical, uleb(1)},
             {2, Criticality::Critical, digest},
             {3, Criticality::Critical, uleb(0)}}
        )) == ErrorKind::Malformed
    );
    CHECK(
        decodeKind(descriptorOf(
            {{1, Criticality::Critical, uleb(1)},
             {2, Criticality::Critical, digest},
             {3, Criticality::Critical, uleb(std::uint64_t{maxChunkSize} + 1)}}
        )) == ErrorKind::LimitExceeded
    );
    CHECK(
        decodeKind(descriptorOf(
            {{1, Criticality::Critical, uleb(1)},
             {2, Criticality::Critical, std::vector<std::byte>(31)},
             {3, Criticality::Critical, uleb(5)}}
        )) == ErrorKind::Malformed
    );
    CHECK(
        decodeKind(descriptorOf(
            {{1, Criticality::Noncritical, uleb(1)},
             {2, Criticality::Critical, digest},
             {3, Criticality::Critical, uleb(5)}}
        )) == ErrorKind::Malformed
    );
    CHECK(
        decodeKind(
            descriptorOf({{1, Criticality::Critical, uleb(1)}, {3, Criticality::Critical, uleb(5)}})
        ) == ErrorKind::Malformed
    );
    CHECK(
        decodeKind(descriptorOf(
            {{1, Criticality::Critical, uleb(1)},
             {2, Criticality::Critical, digest},
             {3, Criticality::Critical, uleb(5)},
             {9, Criticality::Critical, {}}}
        )) == ErrorKind::Unsupported
    );

    CHECK(decodeKind(fromHex("81 01")) == ErrorKind::LimitExceeded);
    CHECK(decodeKind(fromHex("05 03 01")) == ErrorKind::Truncated);

    auto extended = descriptorOf(
        {{1, Criticality::Critical, uleb(1)},
         {2, Criticality::Critical, digest},
         {3, Criticality::Critical, uleb(5)},
         {9, Criticality::Noncritical, uleb(1)}}
    );
    auto decoded = decodeDataPayload(extended, 0);
    REQUIRE(decoded);
    CHECK(decoded->descriptorSize == extended.size());
}

TEST_CASE("INDEX golden bytes round-trip and lookups use the full key") {
    std::vector<IndexEntry> entries{
        IndexEntry{
            .key = syntheticKey(5),
            .recordOffset = 64,
            .recordLength = 102,
            .codec = CodecId::Raw,
        },
    };
    std::vector<std::byte> encoded;
    REQUIRE(encodeIndex(entries, encoded));
    CHECK(encoded == goldenIndex());

    std::vector<IndexEntry> decoded;
    REQUIRE(decodeIndex(goldenIndex(), 0, 10, decoded));
    REQUIRE(decoded.size() == 1);
    CHECK(decoded[0].key == syntheticKey(5));
    CHECK(decoded[0].recordOffset == 64);
    CHECK(decoded[0].recordLength == 102);
    CHECK(findChunk(decoded, syntheticKey(5)) == decoded.data());
    CHECK(findChunk(decoded, syntheticKey(6)) == nullptr);
    CHECK(findChunk(decoded, syntheticKey(5, 1)) == nullptr);

    auto golden = goldenIndex();
    for (std::size_t size = 0; size < golden.size(); ++size) {
        CAPTURE(size);
        CHECK_FALSE(decodeIndex(std::span(golden).first(size), 0, 10, decoded));
    }
}

TEST_CASE("INDEX rejects unsorted, duplicate, out-of-bounds and unknown critical entries") {
    auto element = [](const ChunkKey& key, std::uint64_t offset, std::uint64_t length) {
        std::vector<std::byte> out;
        TlvWriter writer(out);
        REQUIRE(writeChunkKey(writer, key));
        REQUIRE(writer.unsignedValue(4, Criticality::Critical, offset));
        REQUIRE(writer.unsignedValue(5, Criticality::Critical, length));
        REQUIRE(writer.unsignedValue(6, Criticality::Critical, 0));
        return out;
    };
    auto indexOf = [](std::initializer_list<std::vector<std::byte>> elements) {
        return tlv(
            {{1, Criticality::Critical, uleb(1)}, {2, Criticality::Critical, list(elements)}}
        );
    };
    auto errorOf = [](const std::vector<std::byte>& payload, std::uint64_t maxEntries = 10) {
        std::vector<IndexEntry> decoded;
        auto result = decodeIndex(payload, 0, maxEntries, decoded);
        REQUIRE_FALSE(result);
        return result.error().kind;
    };

    auto a = element(syntheticKey(5), 64, 102);
    auto b = element(syntheticKey(5, 1), 200, 102);
    auto shorter = element(syntheticKey(4), 300, 101);
    CHECK(errorOf(indexOf({b, a})) == ErrorKind::Malformed);
    CHECK(errorOf(indexOf({a, a})) == ErrorKind::Malformed);
    CHECK(errorOf(indexOf({a, shorter})) == ErrorKind::Malformed);
    CHECK(errorOf(indexOf({a, b}), 1) == ErrorKind::LimitExceeded);
    CHECK(errorOf(indexOf({element(syntheticKey(5), 63, 102)})) == ErrorKind::Malformed);
    CHECK(errorOf(indexOf({element(syntheticKey(5), 64, 56)})) == ErrorKind::Malformed);
    CHECK(
        errorOf(indexOf({element(syntheticKey(5), ~std::uint64_t{0} - 10, 102)})) ==
        ErrorKind::Malformed
    );

    auto unknown = a;
    std::vector<std::byte> extra;
    TlvWriter writer(extra);
    REQUIRE(writer.bytes(7, Criticality::Critical, {}));
    unknown.insert(unknown.end(), extra.begin(), extra.end());
    CHECK(errorOf(indexOf({unknown})) == ErrorKind::Unsupported);

    std::vector<IndexEntry> decoded;
    CHECK(decodeIndex(indexOf({shorter, a, b}), 0, 10, decoded));
    CHECK(decoded.size() == 3);
}

TEST_CASE("MANIFEST golden bytes cover every entry kind, optional fields and metadata") {
    auto manifest = goldenManifest();
    CHECK(encodedManifest(manifest) == goldenManifestBytes());

    auto golden = goldenManifestBytes();
    Manifest decoded;
    REQUIRE(decodeManifest(golden, 0, {}, decoded));
    REQUIRE(decoded.entries.size() == 4);
    CHECK(decoded.comment == "hi");
    CHECK(decoded.writer == "bale");

    const auto& dir = decoded.entries[0];
    CHECK(dir.path == "d");
    CHECK(dir.kind == EntryKind::Directory);
    CHECK(dir.mode == 0755);
    CHECK_FALSE(dir.mtimeNanoseconds);

    const auto& regular = decoded.entries[1];
    CHECK(regular.kind == EntryKind::Regular);
    CHECK(regular.length == 5);
    CHECK(regular.mtimeNanoseconds == -1);
    REQUIRE(decoded.chunksOf(regular).size() == 1);
    CHECK(decoded.chunksOf(regular)[0] == syntheticKey(5));

    CHECK(decoded.entries[2].kind == EntryKind::HardLink);
    CHECK(decoded.entries[2].target == "d/f");
    CHECK(decoded.entries[3].kind == EntryKind::Symlink);
    CHECK(decoded.entries[3].target == "d/f");
    CHECK(findEntry(decoded.entries, "d/g") == &decoded.entries[2]);
    CHECK(findEntry(decoded.entries, "d/h") == nullptr);

    constexpr std::size_t withoutComment = 123;
    constexpr std::size_t withoutWriter = 127;
    for (std::size_t size = 0; size < golden.size(); ++size) {
        CAPTURE(size);
        auto truncated = decodeBytes(std::span(golden).first(size));
        CHECK(truncated.has_value() == (size == withoutComment || size == withoutWriter));
    }
}

TEST_CASE("MANIFEST rejects ordering, tree and link violations") {
    CHECK(manifestError(manifestOf({file("b"), file("a")})) == ErrorKind::Malformed);
    CHECK(manifestError(manifestOf({file("a"), file("a")})) == ErrorKind::Malformed);
    CHECK(manifestError(manifestOf({file("x/y")})) == ErrorKind::Malformed);
    CHECK(manifestError(manifestOf({file("a"), file("a/b")})) == ErrorKind::Malformed);

    auto link = [](std::string_view path, std::string_view target) {
        return ManifestEntry{
            .path = path,
            .target = target,
            .kind = EntryKind::HardLink,
        };
    };
    CHECK(manifestError(manifestOf({link("a", "b"), file("b")})) == ErrorKind::Malformed);
    CHECK(manifestError(manifestOf({directory("a"), link("b", "a")})) == ErrorKind::Malformed);
    CHECK(manifestError(manifestOf({file("a"), link("c", "b")})) == ErrorKind::Malformed);
    CHECK(
        manifestError(manifestOf({file("a"), link("b", "a"), link("c", "b")})) ==
        ErrorKind::Malformed
    );
    CHECK(decodeBytes(encodedManifest(manifestOf({file("a"), link("b", "a")}))));

    CHECK(decodeBytes(
        encodedManifest(manifestOf({directory("a"), file("a-b"), directory("a/b"), file("a/b/c")}))
    ));
}

TEST_CASE("MANIFEST rejects non-canonical paths but leaves Windows naming rules to extraction") {
    for (auto path :
         {"a/../b"sv, "./a"sv, "a//b"sv, "a/"sv, "/a"sv, "a\\b"sv, "\xFF"sv, "a\0b"sv, ""sv}) {
        CAPTURE(path);
        CHECK(manifestError(manifestOf({file(path)})) == ErrorKind::UnsafePath);
    }

    CHECK(decodeBytes(encodedManifest(manifestOf({file("ab:c"), file("con")}))));

    Limits tight;
    tight.maxPathBytes = 3;
    CHECK(
        decodeBytes(encodedManifest(manifestOf({file("abcd")})), tight).error().kind ==
        ErrorKind::LimitExceeded
    );
    tight = Limits{};
    tight.maxEntries = 1;
    CHECK(
        decodeBytes(encodedManifest(manifestOf({file("a"), file("b")})), tight).error().kind ==
        ErrorKind::LimitExceeded
    );
}

TEST_CASE("MANIFEST enforces per-kind fields and exact chunk coverage") {
    Manifest mismatch = manifestOf({file("a")});
    mismatch.chunks.push_back(syntheticKey(5));
    mismatch.entries[0].length = 6;
    mismatch.entries[0].chunkCount = 1;
    CHECK(manifestError(mismatch) == ErrorKind::Malformed);

    mismatch.entries[0].length = 4;
    CHECK(manifestError(mismatch) == ErrorKind::Malformed);

    mismatch.entries[0].chunkCount = 0;
    mismatch.entries[0].length = 5;
    CHECK(manifestError(mismatch) == ErrorKind::Malformed);

    Manifest badMode = manifestOf({file("a")});
    badMode.entries[0].mode = 010000;
    CHECK(manifestError(badMode) == ErrorKind::Malformed);

    Manifest symlink = manifestOf({ManifestEntry{
        .path = "s",
        .target = "t",
        .mode = 0777,
        .kind = EntryKind::Symlink,
    }});
    CHECK(manifestError(symlink) == ErrorKind::Malformed);
    symlink.entries[0].mode.reset();
    symlink.entries[0].target = "";
    CHECK(manifestError(symlink) == ErrorKind::Malformed);

    Manifest hardLink = manifestOf(
        {file("a"),
         ManifestEntry{
             .path = "b",
             .target = "a",
             .mtimeNanoseconds = 5,
             .kind = EntryKind::HardLink,
         }}
    );
    CHECK(manifestError(hardLink) == ErrorKind::Malformed);

    auto path = [](std::string_view value) {
        return RawField{1, Criticality::Critical, text(value)};
    };
    auto kind = [](EntryKind value) {
        return RawField{2, Criticality::Critical, uleb(static_cast<std::uint64_t>(value))};
    };
    CHECK(
        rawError(rawManifest(
            {tlv({path("a"), kind(EntryKind::Directory), {3, Criticality::Critical, uleb(0)}})}
        )) == ErrorKind::Malformed
    );
    CHECK(
        rawError(rawManifest({tlv({path("a"), {2, Criticality::Critical, uleb(5)}})})) ==
        ErrorKind::Unsupported
    );
    CHECK(
        rawError(rawManifest({tlv(
            {path("a"),
             kind(EntryKind::Regular),
             {3, Criticality::Critical, uleb(0)},
             {4, Criticality::Critical, uleb(0)}}
        )})) == ErrorKind::Malformed
    );
    CHECK(
        rawError(rawManifest({tlv(
            {path("a"),
             kind(EntryKind::Directory),
             {5, Criticality::Critical, std::vector<std::byte>(8)}}
        )})) == ErrorKind::Malformed
    );
    CHECK(
        rawError(rawManifest({tlv(
            {path("a"),
             kind(EntryKind::Directory),
             {5, Criticality::Noncritical, std::vector<std::byte>(4)}}
        )})) == ErrorKind::Malformed
    );
    CHECK(
        rawError(rawManifest(
            {tlv({path("a"), kind(EntryKind::Directory), {20, Criticality::Critical, {}}})}
        )) == ErrorKind::Unsupported
    );
    CHECK(rawError(rawManifest({tlv({kind(EntryKind::Directory)})})) == ErrorKind::Malformed);
    CHECK(decodeBytes(rawManifest(
        {tlv({path("a"), kind(EntryKind::Directory), {20, Criticality::Noncritical, uleb(1)}})}
    )));
}

TEST_CASE("MANIFEST top-level fields need the right version, criticality and no empty defaults") {
    auto entries = list({});
    CHECK(
        decodeBytes(tlv({{1, Criticality::Critical, uleb(1)}, {2, Criticality::Critical, entries}}))
    );
    CHECK(
        rawError(tlv({{1, Criticality::Critical, uleb(2)}, {2, Criticality::Critical, entries}})) ==
        ErrorKind::Unsupported
    );
    CHECK(rawError(tlv({{2, Criticality::Critical, entries}})) == ErrorKind::Malformed);
    CHECK(rawError(tlv({{1, Criticality::Critical, uleb(1)}})) == ErrorKind::Malformed);
    CHECK(
        rawError(
            tlv({{1, Criticality::Noncritical, uleb(1)}, {2, Criticality::Critical, entries}})
        ) == ErrorKind::Malformed
    );
    CHECK(
        rawError(tlv(
            {{1, Criticality::Critical, uleb(1)},
             {2, Criticality::Critical, entries},
             {3, Criticality::Noncritical, {}}}
        )) == ErrorKind::Malformed
    );
    CHECK(
        rawError(tlv(
            {{1, Criticality::Critical, uleb(1)},
             {2, Criticality::Critical, entries},
             {9, Criticality::Critical, {}}}
        )) == ErrorKind::Unsupported
    );
    CHECK(
        rawError(
            tlv({{1, Criticality::Critical, uleb(1)}, {2, Criticality::Critical, fromHex("E8 07")}})
        ) == ErrorKind::Truncated
    );
    CHECK(
        rawError(tlv(
            {{1, Criticality::Critical, uleb(1)},
             {2, Criticality::Critical, fromHex("FF FF FF FF 0F")}}
        )) == ErrorKind::LimitExceeded
    );
}

TEST_CASE("COMMIT golden bytes, digest and schema checks") {
    std::vector<std::byte> encoded;
    REQUIRE(encodeCommit(goldenCommit(), encoded));
    CHECK(encoded == goldenCommitBytes());

    auto digest = Blake3::of(HashDomain::Commit, encoded);
    CHECK(
        std::vector(digest.begin(), digest.end()) ==
        fromHex(
            "BF 20 D3 17 45 FD 5C B7 C1 86 56 1D 12 82 D9 7B 7D 96 12 7B 90 73 6A 74 "
            "3D 56 4C AF B1 26 80 AC"
        )
    );

    auto decoded = decodeCommit(goldenCommitBytes(), 0);
    REQUIRE(decoded);
    CHECK(decoded->generation == 1);
    CHECK(decoded->manifest.offset == 300);
    CHECK(decoded->manifest.length == 120);
    CHECK(decoded->index.offset == 420);
    CHECK(decoded->index.length == 150);
    CHECK(decoded->manifest.digest == goldenCommit().manifest.digest);
    CHECK(decoded->index.digest == goldenCommit().index.digest);

    auto golden = goldenCommitBytes();
    for (std::size_t size = 0; size < golden.size(); ++size) {
        CAPTURE(size);
        CHECK_FALSE(decodeCommit(std::span(golden).first(size), 0));
    }

    auto variant = [](std::uint64_t version, std::uint64_t generation, std::uint64_t features) {
        Commit commit = goldenCommit();
        commit.generation = generation;
        commit.requiredFeatures = features;
        std::vector<std::byte> out;
        REQUIRE(encodeCommit(commit, out));
        out[2] = static_cast<std::byte>(version);
        auto result = decodeCommit(out, 0);
        REQUIRE_FALSE(result);
        return result.error().kind;
    };
    CHECK(variant(2, 1, 0) == ErrorKind::Unsupported);
    CHECK(variant(1, 0, 0) == ErrorKind::Malformed);
    CHECK(variant(1, 1, 1) == ErrorKind::Unsupported);

    auto extended = golden;
    extended.push_back(std::byte{0x16});
    extended.push_back(std::byte{0x00});
    CHECK(decodeCommit(extended, 0));
    extended[extended.size() - 2] = std::byte{0x17};
    CHECK(decodeCommit(extended, 0).error().kind == ErrorKind::Unsupported);

    auto shortDigest = golden;
    shortDigest[7] = std::byte{0x1F};
    CHECK_FALSE(decodeCommit(shortDigest, 0));
}
