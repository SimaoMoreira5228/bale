#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"

#include "archive/archive_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::readAll;
using bale::test::TempFile;
using bale::test::TempPath;

namespace {

std::string noise(std::size_t length) {
    std::string out(length, '\0');
    std::uint32_t value = 0xA341316C;
    for (char& byte : out) {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        byte = static_cast<char>(value & 0xFF);
    }
    return out;
}

std::string contents(Reader& reader, const ManifestEntry& entry) {
    std::string out;
    auto streamed = reader.streamFile(entry, [&out](std::span<const std::byte> chunk) {
        out.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        return Result<void>{};
    });
    REQUIRE(streamed);
    return out;
}

void rewriteCrc(std::vector<std::byte>& bytes, std::uint64_t offset, std::uint64_t length) {
    auto payload = std::span(bytes).subspan(
        static_cast<std::size_t>(offset + recordPrefixSize),
        static_cast<std::size_t>(length - recordFramingSize)
    );
    storeLe(payload.data() + payload.size(), Crc32c::of(payload));
}

Result<Reader> openBytes(std::span<const std::byte> bytes) {
    TempFile file(bytes);
    REQUIRE(file.ok());
    auto opened = file.open();
    REQUIRE(opened);
    return Reader::open(std::move(*opened));
}

}

TEST_CASE("zstd writing compresses useful chunks and keeps incompressible chunks raw") {
    TempPath temp;
    auto file = File::createNew(temp.path());
    REQUIRE(file);
    WriterOptions options;
    options.chunkSize = minChunkSize;
    options.compression.codec = CodecId::Zstd;
    auto writer = Writer::create(std::move(*file), options);
    REQUIRE(writer);

    std::string repeated(minChunkSize, 'x');
    std::string incompressible = noise(minChunkSize);
    REQUIRE(writer->addBytes("repeated", bytesOf(repeated)));
    REQUIRE(writer->addBytes("copy", bytesOf(repeated)));
    REQUIRE(writer->addBytes("pattern", bytesOf(incompressible)));
    auto summary = writer->finish();
    REQUIRE(summary);
    CHECK(summary->dataRecords == 2);
    CHECK(summary->chunkReferences == 3);

    auto readFile = File::openRead(temp.path());
    REQUIRE(readFile);
    auto reader = Reader::open(std::move(*readFile));
    REQUIRE(reader);
    REQUIRE(reader->index().size() == 2);
    CHECK(std::ranges::count(reader->index(), CodecId::Zstd, &IndexEntry::codec) == 1);
    CHECK(std::ranges::count(reader->index(), CodecId::Raw, &IndexEntry::codec) == 1);

    auto repeatedEntry = findEntry(reader->manifest().entries, "repeated");
    auto copyEntry = findEntry(reader->manifest().entries, "copy");
    auto patternEntry = findEntry(reader->manifest().entries, "pattern");
    REQUIRE(repeatedEntry != nullptr);
    REQUIRE(copyEntry != nullptr);
    REQUIRE(patternEntry != nullptr);
    CHECK(contents(*reader, *repeatedEntry) == repeated);
    CHECK(contents(*reader, *copyEntry) == repeated);
    CHECK(contents(*reader, *patternEntry) == incompressible);
    CHECK(reader->verify(VerifyMode::Content));

    TempPath compactedPath;
    auto compactedFile = File::createNew(compactedPath.path());
    REQUIRE(compactedFile);
    auto compactedSummary = Writer::compact(std::move(*compactedFile), *reader);
    REQUIRE(compactedSummary);
    CHECK(compactedSummary->dataRecords == 2);

    auto compactedInput = File::openRead(compactedPath.path());
    REQUIRE(compactedInput);
    auto compacted = Reader::open(std::move(*compactedInput));
    REQUIRE(compacted);
    CHECK(std::ranges::count(compacted->index(), CodecId::Zstd, &IndexEntry::codec) == 1);
    CHECK(std::ranges::count(compacted->index(), CodecId::Raw, &IndexEntry::codec) == 1);
    CHECK(compacted->verify(VerifyMode::Content));

    auto corrupted = readAll(temp.path());
    auto compressedEntry = std::ranges::find(reader->index(), CodecId::Zstd, &IndexEntry::codec);
    REQUIRE(compressedEntry != reader->index().end());
    auto payload = std::span(corrupted).subspan(
        static_cast<std::size_t>(compressedEntry->recordOffset + recordPrefixSize),
        static_cast<std::size_t>(compressedEntry->recordLength - recordFramingSize)
    );
    auto descriptor = decodeDataPayload(payload, compressedEntry->recordOffset + recordPrefixSize);
    REQUIRE(descriptor);
    auto damagedByte = static_cast<std::size_t>(
        compressedEntry->recordOffset + recordPrefixSize + descriptor->descriptorSize
    );
    corrupted[damagedByte] ^= std::byte{0x01};
    rewriteCrc(corrupted, compressedEntry->recordOffset, compressedEntry->recordLength);
    auto damagedReader = openBytes(corrupted);
    REQUIRE(damagedReader);
    CHECK_FALSE(damagedReader->loadChunk(compressedEntry->key));
}
