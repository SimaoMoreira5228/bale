#include "formats/rpm/reader.hpp"

#include "formats/cpio/cpio_fixture.hpp"
#include "formats/detect.hpp"
#include "formats/rpm/rpm_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::rpm;
using namespace bale::rpm::test;

namespace {

ErrorKind errorKind(const Listing& listing) {
    if (!listing.error) {
        FAIL("expected the archive to be rejected");
        return ErrorKind::Io;
    }
    return listing.error->kind;
}

std::string streamAll(Reader& reader, const Entry& entry) {
    std::vector<std::byte> scratch(256);
    std::string text;
    auto streamed = reader.streamEntry(entry, scratch, [&](std::span<const std::byte> chunk) {
        text.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    REQUIRE(streamed);
    return text;
}

Result<Reader> openBytes(std::span<const std::byte> bytes, const Limits& limits = {}) {
    bale::test::TempFile archive(bytes);
    REQUIRE(archive.ok());
    auto file = archive.open();
    REQUIRE(file);
    return Reader::open(std::move(*file), limits);
}

const Entry* findEntry(Reader& reader, std::string_view name) {
    for (const auto& entry : reader.entries()) {
        if (entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

ArchiveFormat detectBytes(std::span<const std::byte> bytes) {
    bale::test::TempFile archive(bytes);
    auto file = archive.open();
    REQUIRE(file);
    auto format = detectFormat(*file);
    REQUIRE(format);
    return *format;
}

}

TEST_CASE("rpm reader lists the golden gzip archive from rpmbuild 6.0.2") {
    // NOTE: tests/formats/rpm/data/hello-gzip.rpm was built by
    // `rpmbuild -bb` from RPM 6.0.2 with `_binary_payload w9.gzdio`.
    // Fedora's buildroot policy rewrote run.sh's `#!/bin/sh` shebang to
    // `#!/usr/bin/sh`, which the payload assertions pin down.
    auto reader = openBytes(golden("hello-gzip.rpm"));
    REQUIRE(reader);

    const auto& package = reader->package();
    CHECK(package.name == "hello-pkg");
    CHECK(package.version == "1.0");
    CHECK(package.release == "1cgz");
    CHECK(package.arch == "noarch");
    CHECK(package.os == "linux");
    CHECK(package.payloadFormat == "cpio");
    CHECK(package.payloadCompressor == "gzip");
    CHECK(package.compression == Compression::Gzip);
    CHECK_FALSE(package.uncompressed);
    CHECK(package.payloadBytes > 0);
    CHECK_FALSE(package.signatureTags.empty());

    REQUIRE(reader->entryCount() == 3);
    const auto* greeting = findEntry(*reader, "./usr/share/hello/greeting.txt");
    const auto* link = findEntry(*reader, "./usr/share/hello/link.txt");
    const auto* run = findEntry(*reader, "./usr/share/hello/run.sh");
    REQUIRE(greeting != nullptr);
    REQUIRE(link != nullptr);
    REQUIRE(run != nullptr);
    CHECK(greeting->size == 10);
    CHECK(greeting->kind == EntryKind::Regular);
    CHECK(greeting->mode == 0100644);
    CHECK(link->kind == EntryKind::Symlink);
    CHECK(link->size == 12);
    CHECK(run->mode == 0100755);
    CHECK(streamAll(*reader, *greeting) == "hello rpm\n");
    CHECK(streamAll(*reader, *link) == "greeting.txt");
    CHECK(streamAll(*reader, *run) == "#!/usr/bin/sh\necho hi\n");

    CHECK(detectBytes(golden("hello-gzip.rpm")) == ArchiveFormat{.container = Container::Rpm});
    CHECK(name(ArchiveFormat{.container = Container::Rpm}) == "rpm");
    CHECK_FALSE(looksLikeRpm(
        std::array<std::byte, 4>{
            std::byte{'P'},
            std::byte{'K'},
            std::byte{3},
            std::byte{4},
        }
    ));
}

TEST_CASE("rpm reader decodes every payload compressor identically") {
    // NOTE: hello-{gzip,xz,zstd,bzip2}.rpm share one spec; only
    // `_binary_payload` differs (w9.gzdio, w9.xzdio, w19.zstdio, w2.bzdio).
    for (std::string_view name :
         {"hello-gzip.rpm", "hello-xz.rpm", "hello-zstd.rpm", "hello-bzip2.rpm"}) {
        CAPTURE(name);
        auto reader = openBytes(golden(name));
        REQUIRE(reader);
        REQUIRE(reader->entryCount() == 3);
        const auto* greeting = findEntry(*reader, "./usr/share/hello/greeting.txt");
        REQUIRE(greeting != nullptr);
        CHECK(streamAll(*reader, *greeting) == "hello rpm\n");
    }

    CHECK(openBytes(golden("hello-xz.rpm"))->package().compression == Compression::Xz);
    CHECK(openBytes(golden("hello-zstd.rpm"))->package().compression == Compression::Zstd);
    CHECK(openBytes(golden("hello-bzip2.rpm"))->package().compression == Compression::Bzip2);
}

TEST_CASE("rpm reader surfaces signature presence without verifying") {
    auto reader = openBytes(golden("hello-gzip.rpm"));
    REQUIRE(reader);
    // NOTE: the golden is unsigned, yet rpmbuild still emits size and
    // digest tags; presence is informational, never a trust verdict.
    CHECK(reader->package().signatureTags.size() == 7);

    std::uint64_t offset = 0;
    auto payload = payloadSlice(golden("hello-gzip.rpm"), offset);
    auto unsigned_ = buildPackage({}, minimalTags(), payload);
    auto rebuilt = openBytes(unsigned_);
    REQUIRE(rebuilt);
    CHECK(rebuilt->package().signatureTags.empty());
    CHECK(rebuilt->entryCount() == 3);
}

TEST_CASE("rpm reader passes uncompressed payloads through") {
    cpio::test::ArchiveBuilder builder;
    cpio::test::EntrySpec spec;
    spec.name = "plain.txt";
    spec.data = "uncompressed\n";
    builder.entry(spec).trailer();

    auto package = buildPackage({}, minimalTags("none"), builder.bytes());
    auto reader = openBytes(package);
    REQUIRE(reader);
    CHECK(reader->package().uncompressed);
    REQUIRE(reader->entryCount() == 1);
    CHECK(reader->entries()[0].name == "plain.txt");
}

TEST_CASE("rpm reader refuses unknown compressors and payload formats") {
    std::uint64_t offset = 0;
    auto payload = payloadSlice(golden("hello-gzip.rpm"), offset);

    auto lzma = buildPackage({}, minimalTags("lzma"), payload);
    CHECK(errorKind(listArchive(lzma)) == ErrorKind::Unsupported);

    auto tags = minimalTags();
    for (auto& tag : tags) {
        if (tag.tag == tagPayloadFormat) {
            tag.data.clear();
            for (char unit : std::string_view("tar")) {
                tag.data.push_back(static_cast<std::byte>(unit));
            }
            tag.data.push_back(std::byte{0});
        }
    }
    auto tar = buildPackage({}, tags, payload);
    CHECK(errorKind(listArchive(tar)) == ErrorKind::Unsupported);
}

TEST_CASE("rpm reader refuses legacy and unknown lead versions") {
    std::uint64_t offset = 0;
    auto payload = payloadSlice(golden("hello-gzip.rpm"), offset);

    auto ancient = buildPackage({}, minimalTags(), payload, 1);
    CHECK(errorKind(listArchive(ancient)) == ErrorKind::Unsupported);

    auto future = buildPackage({}, minimalTags(), payload, 9);
    CHECK(errorKind(listArchive(future)) == ErrorKind::Malformed);

    auto bytes = golden("hello-gzip.rpm");
    bytes[0] = std::byte{'P'};
    CHECK(errorKind(listArchive(bytes)) == ErrorKind::Malformed);
}

TEST_CASE("rpm reader accepts padded and unpadded header layouts") {
    std::uint64_t offset = 0;
    auto payload = payloadSlice(golden("hello-gzip.rpm"), offset);

    auto padded = buildPackage({}, minimalTags(), payload, majorV3, false);
    auto paddedReader = openBytes(padded);
    REQUIRE(paddedReader);
    CHECK(paddedReader->entryCount() == 3);

    auto lead = buildLead(majorV3);
    auto signature = buildRecord({}, false);
    auto header = buildRecord(minimalTags(), false);
    std::vector<std::byte> tight;
    tight.insert(tight.end(), lead.begin(), lead.end());
    tight.insert(tight.end(), signature.begin(), signature.end());
    tight.insert(tight.end(), header.begin(), header.end());
    tight.insert(tight.end(), payload.begin(), payload.end());
    auto tightReader = openBytes(tight);
    REQUIRE(tightReader);
    CHECK(tightReader->entryCount() == 3);
}

TEST_CASE("rpm reader rejects truncated archives at every boundary") {
    auto full = golden("hello-gzip.rpm");
    std::uint64_t offset = 0;
    static_cast<void>(payloadSlice(full, offset));
    for (std::size_t cut = 0; cut < full.size(); ++cut) {
        CAPTURE(cut);
        auto prefix =
            std::vector<std::byte>(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut));
        if (cut < leadMagic.size()) {
            CHECK(errorKind(listArchive(prefix)) == ErrorKind::Malformed);
        } else {
            auto kind = errorKind(listArchive(prefix));
            bool structural = kind == ErrorKind::Truncated || kind == ErrorKind::Malformed;
            CHECK(structural);
        }
    }
}

TEST_CASE("rpm reader enforces caller limits before allocating") {
    Limits entries;
    entries.maxHeaderEntries = 1;
    CHECK(errorKind(listArchive(golden("hello-gzip.rpm"), entries)) == ErrorKind::LimitExceeded);

    Limits store;
    store.maxHeaderBytes = 10;
    CHECK(errorKind(listArchive(golden("hello-gzip.rpm"), store)) == ErrorKind::LimitExceeded);

    Limits strings;
    strings.maxStringBytes = 1;
    CHECK(errorKind(listArchive(golden("hello-gzip.rpm"), strings)) == ErrorKind::LimitExceeded);

    Limits signatures;
    signatures.maxSignatureTags = 1;
    CHECK(errorKind(listArchive(golden("hello-gzip.rpm"), signatures)) == ErrorKind::LimitExceeded);

    Limits output;
    output.decompress.maxOutputBytes = 1;
    CHECK(errorKind(listArchive(golden("hello-gzip.rpm"), output)) == ErrorKind::LimitExceeded);

    Limits payloadEntries;
    payloadEntries.cpio.maxEntries = 1;
    CHECK(
        errorKind(listArchive(golden("hello-gzip.rpm"), payloadEntries)) == ErrorKind::LimitExceeded
    );

    Limits payloadTotal;
    payloadTotal.cpio.maxTotalBytes = 1;
    CHECK(
        errorKind(listArchive(golden("hello-gzip.rpm"), payloadTotal)) == ErrorKind::LimitExceeded
    );
}

TEST_CASE("rpm reader rejects header lies without allocating") {
    std::uint64_t offset = 0;
    auto payload = payloadSlice(golden("hello-gzip.rpm"), offset);

    auto missing = minimalTags();
    missing.erase(
        std::remove_if(
            missing.begin(),
            missing.end(),
            [](const RawTag& tag) {
                return tag.tag == tagName;
            }
        ),
        missing.end()
    );
    CHECK(errorKind(listArchive(buildPackage({}, missing, payload))) == ErrorKind::Malformed);

    auto unterminated = minimalTags();
    for (auto& tag : unterminated) {
        if (tag.tag == tagPayloadFlags) {
            tag.data.pop_back();
        }
    }
    CHECK(errorKind(listArchive(buildPackage({}, unterminated, payload))) == ErrorKind::Malformed);

    // NOTE: the lies below stay under the caller limits so the reader
    // reports truncation instead of LimitExceeded.
    // The signature record sits at 96: count at 104, store size at 108.
    auto full = golden("hello-gzip.rpm");
    auto hugeCount = full;
    hugeCount[104] = std::byte{0};
    hugeCount[105] = std::byte{0x01};
    hugeCount[106] = std::byte{0x86};
    hugeCount[107] = std::byte{0xA0};
    CHECK(errorKind(listArchive(hugeCount)) == ErrorKind::Truncated);

    auto hugeStore = full;
    hugeStore[108] = std::byte{0};
    hugeStore[109] = std::byte{0x10};
    hugeStore[110] = std::byte{0};
    hugeStore[111] = std::byte{0};
    CHECK(errorKind(listArchive(hugeStore)) == ErrorKind::Truncated);

    // NOTE: the first signature index entry (at 112: tag, type, offset,
    // count) points past the store, then carries a bad type instead.
    auto badOffset = full;
    badOffset[120] = std::byte{0xFF};
    badOffset[121] = std::byte{0xFF};
    badOffset[122] = std::byte{0xFF};
    badOffset[123] = std::byte{0xFF};
    CHECK(errorKind(listArchive(badOffset)) == ErrorKind::Malformed);

    auto badType = full;
    badType[116] = std::byte{0xFF};
    badType[117] = std::byte{0xFF};
    badType[118] = std::byte{0xFF};
    badType[119] = std::byte{0xFF};
    CHECK(errorKind(listArchive(badType)) == ErrorKind::Malformed);

    auto empty = buildPackage({}, minimalTags(), {});
    CHECK(errorKind(listArchive(empty)) == ErrorKind::Truncated);
}
