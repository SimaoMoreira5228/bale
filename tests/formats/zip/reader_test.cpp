#include "formats/zip/reader.hpp"

#include "zip_fixture.hpp"

#include <doctest/doctest.h>

#include <array>
#include <string>
#include <utility>
#include <vector>

using namespace bale;
using namespace bale::zip::test;

namespace {

Result<zip::Reader> openZip(const TempFile& temp, const zip::Limits& limits = {}) {
    REQUIRE(temp.ok());
    auto file = temp.open();
    REQUIRE(file);
    return zip::Reader::open(std::move(*file), limits);
}

std::vector<zip::Entry> collect(const zip::Reader& reader) {
    std::vector<zip::Entry> entries;
    auto cursor = reader.entries();
    zip::Entry entry;
    while (true) {
        auto more = cursor.next(entry);
        REQUIRE(more);
        if (!*more) {
            break;
        }
        entries.push_back(entry);
    }
    return entries;
}

std::string readAll(const zip::Reader& reader, const zip::Entry& entry) {
    std::string text(entry.uncompressedSize, '\0');
    auto out = std::as_writable_bytes(std::span(text.data(), text.size()));
    auto read = reader.readStored(entry, out);
    REQUIRE(read);
    return text;
}

void checkRejected(
    const Bytes& bytes,
    ErrorKind kind,
    std::string_view what,
    const zip::Limits& limits = {}
) {
    TempFile temp(bytes);
    auto reader = openZip(temp, limits);
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == kind);
    CHECK(reader.error().what == what);
}

Bytes timestampExtra(std::int32_t mtime) {
    Bytes extra;
    put16(extra, 0x5455);
    put16(extra, 5);
    extra.push_back(std::byte{0x01});
    put32(extra, static_cast<std::uint32_t>(mtime));
    return extra;
}

ZipSpec twoEntrySpec() {
    ZipSpec spec;
    spec.entries.push_back({.name = "docs/readme.txt", .data = "hello, stored world\n"});
    spec.entries.push_back({.name = "empty/", .data = ""});
    return spec;
}

}

TEST_CASE("ZIP reader lists stored entries with metadata and reads their data") {
    ZipSpec spec = twoEntrySpec();
    spec.entries[0].flags = zip::flagUtf8;
    spec.entries[0].centralExtra = timestampExtra(1'700'000'000);
    spec.entries[1].madeBy = 0x0014;
    spec.comment = "archive comment";

    auto built = buildZip(spec);
    TempFile temp(built.bytes);
    auto reader = openZip(temp);
    REQUIRE(reader);
    CHECK(reader->entryCount() == 2);
    CHECK(reader->comment() == "archive comment");
    CHECK(reader->prefixSize() == 0);
    CHECK_FALSE(reader->zip64());

    auto entries = collect(*reader);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].name == "docs/readme.txt");
    CHECK(entries[0].utf8Name());
    CHECK(entries[0].modifiedUnixTime == 1'700'000'000);
    CHECK(entries[0].unixMode == 0100644);
    CHECK(entries[0].localHeaderOffset == 0);
    CHECK(entries[1].name == "empty/");
    CHECK_FALSE(entries[1].unixMode);
    CHECK_FALSE(entries[1].modifiedUnixTime);

    auto stamp = zip::decodeDosDateTime(entries[0].dosDate, entries[0].dosTime);
    CHECK(stamp.year == 2025);
    CHECK(stamp.month == 10);
    CHECK(stamp.day == 17);
    CHECK(stamp.hour == 13);
    CHECK(stamp.minute == 25);
    CHECK(stamp.second == 20);

    CHECK(readAll(*reader, entries[0]) == "hello, stored world\n");
    CHECK(readAll(*reader, entries[1]).empty());

    std::array<std::byte, 3> scratch{};
    std::string streamed;
    std::size_t chunks = 0;
    auto result = reader->streamStored(entries[0], scratch, [&](std::span<const std::byte> chunk) {
        streamed.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        ++chunks;
        return Result<void>{};
    });
    REQUIRE(result);
    CHECK(streamed == "hello, stored world\n");
    CHECK(chunks == 7);

    CHECK(collect(*reader).size() == 2);
}

TEST_CASE("ZIP reader accepts data descriptors and checks the local header against central") {
    ZipSpec spec;
    spec.entries.push_back({.name = "a.bin", .data = "descriptor data", .flags = 0x0008});
    spec.entries.push_back({.name = "b.bin", .data = "second"});
    auto built = buildZip(spec);

    TempFile temp(built.bytes);
    auto reader = openZip(temp);
    REQUIRE(reader);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 2);
    CHECK(entries[0].hasDataDescriptor());
    CHECK(readAll(*reader, entries[0]) == "descriptor data");
    CHECK(readAll(*reader, entries[1]) == "second");

    auto dataStart = reader->dataOffset(entries[1]);
    REQUIRE(dataStart);
    CHECK(*dataStart == entries[1].localHeaderOffset + 30 + 5);

    auto local = static_cast<std::size_t>(entries[1].localHeaderOffset);
    auto tampered = built.bytes;
    std::string_view expected;
    SUBCASE("method differs") {
        patch16(tampered, local + 8, zip::methodDeflate);
        expected = "local header method differs from central";
    }
    SUBCASE("encryption flag differs") {
        patch16(tampered, local + 6, zip::flagEncrypted);
        expected = "local header flags differ from central";
    }
    SUBCASE("name differs") {
        tampered[local + 30] = std::byte{'c'};
        expected = "local header name differs from central";
    }
    SUBCASE("CRC-32 differs without data descriptor") {
        patch32(tampered, local + 14, 0);
        expected = "local header disagrees with central";
    }

    TempFile tamperedFile(tampered);
    auto other = openZip(tamperedFile);
    REQUIRE(other);
    auto offset = other->dataOffset(collect(*other)[1]);
    REQUIRE_FALSE(offset);
    CHECK(offset.error().kind == ErrorKind::Malformed);
    CHECK(offset.error().what == expected);
}

TEST_CASE("ZIP reader resolves ZIP64 extra fields and the ZIP64 end record") {
    ZipSpec spec;
    spec.entries.push_back({.name = "small", .data = "abc"});
    spec.entries.push_back({.name = "big", .data = "zip64 payload", .zip64 = true});
    spec.zip64End = true;
    spec.comment = "z";
    auto built = buildZip(spec);

    TempFile temp(built.bytes);
    auto reader = openZip(temp);
    REQUIRE(reader);
    CHECK(reader->zip64());
    CHECK(reader->entryCount() == 2);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 2);
    CHECK(entries[1].uncompressedSize == 13);
    CHECK(entries[1].compressedSize == 13);
    CHECK(entries[1].localHeaderOffset == 30 + 5 + 3);
    CHECK(readAll(*reader, entries[1]) == "zip64 payload");

    SUBCASE("prepended bytes shift the ZIP64 records too") {
        spec.prefix = Bytes(100, std::byte{0x90});
        auto shifted = buildZip(spec);
        TempFile shiftedFile(shifted.bytes);
        auto shiftedReader = openZip(shiftedFile);
        REQUIRE(shiftedReader);
        CHECK(shiftedReader->prefixSize() == 100);
        CHECK(readAll(*shiftedReader, collect(*shiftedReader)[1]) == "zip64 payload");
    }
    SUBCASE("ZIP64 extra shorter than the saturated fields") {
        auto broken = built.bytes;
        auto extraSize = built.directoryStart + 46 + 5 + 46 + 3 + 2;
        REQUIRE(broken[extraSize] == std::byte{24});
        patch16(broken, extraSize, 16);
        checkRejected(broken, ErrorKind::Malformed, "ZIP64 extra field too short");
    }
    SUBCASE("saturated fields without ZIP64 extra") {
        auto broken = built.bytes;
        auto extraId = built.directoryStart + 46 + 5 + 46 + 3;
        patch16(broken, extraId, 0x7777);
        checkRejected(broken, ErrorKind::Malformed, "saturated field without ZIP64 extra");
    }
    SUBCASE("ZIP64 end record disagrees with a non-saturated end record field") {
        auto broken = built.bytes;
        patch16(broken, built.endStart + 10, 5);
        checkRejected(broken, ErrorKind::Malformed, "end record disagrees with ZIP64 end record");
    }
    SUBCASE("saturated end record without a locator") {
        auto broken = built.bytes;
        patch32(broken, built.endStart - 20, 0);
        checkRejected(broken, ErrorKind::Malformed, "saturated end record without ZIP64 locator");
    }
}

TEST_CASE("ZIP reader tolerates prepended data only when offsets are consistent") {
    ZipSpec spec = twoEntrySpec();
    spec.prefix = Bytes(37, std::byte{0x4D});
    auto built = buildZip(spec);

    TempFile temp(built.bytes);
    auto reader = openZip(temp);
    REQUIRE(reader);
    CHECK(reader->prefixSize() == 37);
    auto entries = collect(*reader);
    CHECK(entries[0].localHeaderOffset == 0);
    CHECK(readAll(*reader, entries[0]) == "hello, stored world\n");

    auto pastLocation = built.bytes;
    patch32(
        pastLocation,
        built.endStart + 16,
        static_cast<std::uint32_t>(built.directoryStart + 1)
    );
    checkRejected(
        pastLocation,
        ErrorKind::Malformed,
        "central directory offset beyond its location"
    );

    auto gap = built.bytes;
    patch32(
        gap,
        built.endStart + 12,
        static_cast<std::uint32_t>(built.endStart - built.directoryStart - 1)
    );
    checkRejected(gap, ErrorKind::Malformed, "no central directory at computed offset");
}

TEST_CASE("ZIP reader skips fake end records inside the archive comment") {
    ZipSpec spec = twoEntrySpec();
    Bytes fake;
    put32(fake, 0x06054b50);
    put16(fake, 0);
    put16(fake, 0);
    put16(fake, 9);
    put16(fake, 9);
    put32(fake, 0x1000);
    put32(fake, 0x20);
    put16(fake, 3);
    spec.comment.assign(reinterpret_cast<const char*>(fake.data()), fake.size());
    spec.comment += "end";

    SUBCASE("fake reaching EOF with bogus directory") {
    }
    SUBCASE("fake not reaching EOF") {
        spec.comment += "!";
    }

    auto built = buildZip(spec);
    TempFile temp(built.bytes);
    auto reader = openZip(temp);
    REQUIRE(reader);
    CHECK(reader->entryCount() == 2);
    CHECK(reader->comment() == spec.comment);
    CHECK(readAll(*reader, collect(*reader)[0]) == "hello, stored world\n");
}

TEST_CASE("ZIP reader rejects inconsistent end records and central directories") {
    std::vector<ZipEntrySpec> longNames{
        {.name = std::string(40, 'a'), .data = "1"},
        {.name = std::string(40, 'b'), .data = "2"},
    };

    SUBCASE("entry count lower than headers present") {
        ZipSpec spec{.entries = longNames, .entryCount = 1};
        checkRejected(
            buildZip(spec).bytes,
            ErrorKind::Malformed,
            "central directory has more data than its entry count"
        );
    }
    SUBCASE("entry count higher than headers present") {
        ZipSpec spec{.entries = longNames, .entryCount = 3};
        checkRejected(
            buildZip(spec).bytes,
            ErrorKind::Malformed,
            "central directory has fewer entries than its entry count"
        );
    }
    SUBCASE("entry count that cannot fit the directory size") {
        ZipSpec spec{.entries = longNames, .entryCount = 50};
        checkRejected(
            buildZip(spec).bytes,
            ErrorKind::Malformed,
            "entry count does not fit central directory"
        );
    }
    SUBCASE("central directory offset beyond the file") {
        ZipSpec spec{.entries = longNames, .directoryOffset = 0xFFFFFF00};
        checkRejected(
            buildZip(spec).bytes,
            ErrorKind::Malformed,
            "central directory offset beyond its location"
        );
    }
    SUBCASE("central directory size beyond the file") {
        auto built = buildZip({.entries = longNames});
        patch32(built.bytes, built.endStart + 12, 0x7FFFFFFF);
        checkRejected(built.bytes, ErrorKind::Malformed, "central directory larger than the file");
    }
    SUBCASE("multi-disk archive") {
        ZipSpec spec{.entries = longNames, .disk = 1};
        checkRejected(
            buildZip(spec).bytes,
            ErrorKind::Unsupported,
            "multi-disk archives are not supported"
        );
    }
    SUBCASE("local header offset pointing into the central directory") {
        auto built = buildZip({.entries = longNames});
        patch32(
            built.bytes,
            built.directoryStart + 42,
            static_cast<std::uint32_t>(built.directoryStart - 10)
        );
        checkRejected(
            built.bytes,
            ErrorKind::Malformed,
            "local header offset outside the data area"
        );
    }
    SUBCASE("no end record at all") {
        auto built = buildZip({.entries = longNames});
        built.bytes[built.endStart] = std::byte{0};
        checkRejected(built.bytes, ErrorKind::Malformed, "end of central directory not found");
    }
}

TEST_CASE("ZIP reader validates extra field framing strictly") {
    ZipSpec spec = twoEntrySpec();
    std::string_view expected;

    SUBCASE("extra field length overflowing the extra area") {
        expected = "extra field overruns its area";
        Bytes extra;
        put16(extra, 0xCAFE);
        put16(extra, 0xFFF0);
        put32(extra, 0);
        spec.entries[0].centralExtra = extra;
    }
    SUBCASE("trailing bytes shorter than an extra header") {
        expected = "truncated extra field header";
        spec.entries[0].centralExtra = timestampExtra(5);
        spec.entries[0].centralExtra.push_back(std::byte{0});
        spec.entries[0].centralExtra.push_back(std::byte{0});
    }
    SUBCASE("timestamp claiming mtime without room for it") {
        expected = "extended timestamp extra field too short";
        Bytes extra;
        put16(extra, 0x5455);
        put16(extra, 2);
        put16(extra, 0x0001);
        spec.entries[0].centralExtra = extra;
    }
    SUBCASE("duplicate ZIP64 extra") {
        expected = "duplicate ZIP64 extra field";
        spec.entries[0].zip64 = true;
        Bytes extra;
        put16(extra, 0x0001);
        put16(extra, 0);
        spec.entries[0].centralExtra = extra;
    }

    checkRejected(buildZip(spec).bytes, ErrorKind::Malformed, expected);
}

TEST_CASE("ZIP reader enforces caller limits before allocating") {
    auto built = buildZip(twoEntrySpec());
    checkRejected(
        built.bytes,
        ErrorKind::LimitExceeded,
        "entry count exceeds limit",
        {.maxEntries = 1}
    );
    checkRejected(
        built.bytes,
        ErrorKind::LimitExceeded,
        "central directory exceeds limit",
        {.maxCentralDirectoryBytes = 64}
    );
    checkRejected(
        built.bytes,
        ErrorKind::LimitExceeded,
        "entry name exceeds limit",
        {.maxNameLength = 10}
    );

    TempFile temp(built.bytes);
    CHECK(openZip(temp, {.maxEntries = 2, .maxCentralDirectoryBytes = 113, .maxNameLength = 15}));
}

TEST_CASE("ZIP reader rejects bad entry data access") {
    ZipSpec spec = twoEntrySpec();
    spec.entries.push_back({.name = "bad-crc", .data = "payload", .crc = 0x12345678});
    spec.entries.push_back({.name = "deflated", .data = "xx", .method = zip::methodDeflate});
    spec.entries.push_back({.name = "locked", .data = "xx", .flags = zip::flagEncrypted});
    auto built = buildZip(spec);

    TempFile temp(built.bytes);
    auto reader = openZip(temp);
    REQUIRE(reader);
    auto entries = collect(*reader);
    REQUIRE(entries.size() == 5);

    std::array<std::byte, 7> out{};
    auto badCrc = reader->readStored(entries[2], out);
    REQUIRE_FALSE(badCrc);
    CHECK(badCrc.error().kind == ErrorKind::Integrity);

    std::array<std::byte, 4> scratch{};
    auto sink = [](std::span<const std::byte>) {
        return Result<void>{};
    };
    auto streamed = reader->streamStored(entries[2], scratch, sink);
    REQUIRE_FALSE(streamed);
    CHECK(streamed.error().kind == ErrorKind::Integrity);

    std::array<std::byte, 2> small{};
    auto deflated = reader->readStored(entries[3], small);
    REQUIRE_FALSE(deflated);
    CHECK(deflated.error().kind == ErrorKind::Unsupported);
    CHECK(deflated.error().what == "deflate decompression is not implemented yet");

    auto locked = reader->readStored(entries[4], small);
    REQUIRE_FALSE(locked);
    CHECK(locked.error().kind == ErrorKind::Unsupported);

    auto wrongSize = reader->readStored(entries[0], small);
    REQUIRE_FALSE(wrongSize);
    CHECK(wrongSize.error().kind == ErrorKind::LimitExceeded);

    auto failing = reader->streamStored(entries[0], scratch, [](std::span<const std::byte>) {
        return Result<void>{fail(ErrorKind::Io, "sink full")};
    });
    REQUIRE_FALSE(failing);
    CHECK(failing.error().what == "sink full");
}

TEST_CASE("ZIP reader reports a truncated local header that overruns the data area") {
    auto built = buildZip(twoEntrySpec());
    patch16(built.bytes, 26, 0xFFFF);

    TempFile temp(built.bytes);
    auto reader = openZip(temp);
    REQUIRE(reader);
    auto offset = reader->dataOffset(collect(*reader)[0]);
    REQUIRE_FALSE(offset);
    CHECK(offset.error().kind == ErrorKind::Truncated);
}

TEST_CASE("ZIP reader fails cleanly on every truncation and single-byte corruption") {
    ZipSpec spec = twoEntrySpec();
    spec.entries[0].zip64 = true;
    spec.entries[1].centralExtra = timestampExtra(42);
    spec.zip64End = true;
    spec.comment = "c";
    auto built = buildZip(spec);

    for (std::size_t length = 0; length < built.bytes.size(); ++length) {
        Bytes truncated(
            built.bytes.begin(),
            built.bytes.begin() + static_cast<std::ptrdiff_t>(length)
        );
        TempFile temp(truncated);
        CHECK_FALSE(openZip(temp));
    }

    std::array<std::byte, 64> scratch{};
    for (std::size_t index = 0; index < built.bytes.size(); ++index) {
        auto corrupted = built.bytes;
        corrupted[index] ^= std::byte{0xA5};
        TempFile temp(corrupted);
        auto reader = openZip(temp);
        if (!reader) {
            continue;
        }

        auto cursor = reader->entries();
        zip::Entry entry;
        while (true) {
            auto more = cursor.next(entry);
            REQUIRE(more);
            if (!*more) {
                break;
            }
            auto ignored = reader->streamStored(entry, scratch, [](std::span<const std::byte>) {
                return Result<void>{};
            });
            static_cast<void>(ignored);
        }
    }
}

TEST_CASE("looksLikeZip detects local headers and end records reaching EOF") {
    auto built = buildZip(twoEntrySpec());
    CHECK(zip::looksLikeZip(built.bytes, built.bytes));

    ZipSpec empty;
    empty.comment = "only a comment";
    auto emptyZip = buildZip(empty);
    CHECK(zip::looksLikeZip(emptyZip.bytes, emptyZip.bytes));

    TempFile temp(emptyZip.bytes);
    auto reader = openZip(temp);
    REQUIRE(reader);
    CHECK(reader->entryCount() == 0);

    auto shortened = emptyZip.bytes;
    shortened.pop_back();
    CHECK_FALSE(zip::looksLikeZip(shortened, shortened));

    Bytes noise(300, std::byte{0x50});
    CHECK_FALSE(zip::looksLikeZip(noise, noise));
    CHECK_FALSE(zip::looksLikeZip({}, {}));
}
