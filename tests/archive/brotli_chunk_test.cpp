#include "archive/chunk_codec.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/record.hpp"

#include "archive/archive_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <span>
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
    std::uint32_t value = 0x8E5F7A21;
    for (char& byte : out) {
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        byte = static_cast<char>(value & 0xFF);
    }
    return out;
}

WriterOptions brotliOptions(int level) {
    WriterOptions options = test::fixedOptions(minChunkSize);
    options.compression.codec = CodecId::Brotli;
    options.compression.level = level;
    options.compression.preset.reset();
    return options;
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

TEST_CASE("brotli chunk round trips pin the codec id and refuse unknown codecs") {
    CHECK(codecName(CodecId::Brotli) == "brotli");
    CHECK(static_cast<std::uint32_t>(CodecId::Brotli) == 4);

    std::string text(minChunkSize, 'x');
    for (int level : {0, 1, 6, 11}) {
        CAPTURE(level);
        auto profile = CompressionProfile{
            .preset = std::nullopt,
            .codec = CodecId::Brotli,
            .level = level,
        };
        auto encoder = ChunkEncoder::create(profile, minChunkSize);
        REQUIRE(encoder);
        auto encoded = encoder->encode(bytesOf(text));
        REQUIRE(encoded);
        CHECK(encoded->codec == CodecId::Brotli);

        ChunkDecoder decoder;
        std::vector<std::byte> output(minChunkSize);
        REQUIRE(decoder.decode(encoded->codec, encoded->bytes, output));
        CHECK(std::ranges::equal(output, bytesOf(text)));
    }

    auto badLevel = CompressionProfile{
        .preset = std::nullopt,
        .codec = CodecId::Brotli,
        .level = 12,
    };
    CHECK_FALSE(ChunkEncoder::create(badLevel, minChunkSize));

    ChunkDecoder decoder;
    std::vector<std::byte> output(16);
    auto unknown = decoder.decode(static_cast<CodecId>(99), bytesOf(text), output);
    REQUIRE_FALSE(unknown);
    CHECK(unknown.error().kind == ErrorKind::Unsupported);
}


TEST_CASE("brotli writing compresses useful chunks and keeps incompressible chunks raw") {
    TempPath temp;
    auto file = File::createNew(temp.path());
    REQUIRE(file);
    auto writer = Writer::create(std::move(*file), brotliOptions(6));
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
    CHECK(std::ranges::count(reader->index(), CodecId::Brotli, &IndexEntry::codec) == 1);
    CHECK(std::ranges::count(reader->index(), CodecId::Raw, &IndexEntry::codec) == 1);

    auto repeatedEntry = findEntry(reader->manifest().entries, "repeated");
    REQUIRE(repeatedEntry != nullptr);
    CHECK(test::contents(*reader, *repeatedEntry) == repeated);
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("the reader rejects hostile brotli chunks behind a valid record checksum") {
    TempPath temp;
    auto file = File::createNew(temp.path());
    REQUIRE(file);
    auto writer = Writer::create(std::move(*file), brotliOptions(6));
    REQUIRE(writer);

    std::string text(minChunkSize, 'y');
    REQUIRE(writer->addBytes("text", bytesOf(text)));
    REQUIRE(writer->finish());

    auto original = readAll(temp.path());
    auto readFile = File::openRead(temp.path());
    REQUIRE(readFile);
    auto reader = Reader::open(std::move(*readFile));
    REQUIRE(reader);
    REQUIRE(reader->index().size() == 1);
    const IndexEntry entry = reader->index().front();
    REQUIRE(entry.codec == CodecId::Brotli);

    auto payloadOffset = entry.recordOffset + recordPrefixSize;
    auto payload = std::span(original).subspan(
        static_cast<std::size_t>(payloadOffset),
        static_cast<std::size_t>(entry.recordLength - recordFramingSize)
    );
    auto data = decodeDataPayload(payload, payloadOffset);
    REQUIRE(data);
    auto frameAt = static_cast<std::size_t>(payloadOffset + data->descriptorSize);
    auto frameSize = data->encoded.size();

    auto rejects = [&](auto damage) {
        auto bytes = original;
        damage(std::span(bytes).subspan(frameAt, frameSize));
        rewriteCrc(bytes, entry.recordOffset, entry.recordLength);
        auto damaged = openBytes(bytes);
        REQUIRE(damaged);
        CHECK_FALSE(damaged->loadChunk(entry.key));
        CHECK_FALSE(damaged->verify(VerifyMode::Content));
    };

    rejects([](std::span<std::byte> frame) {
        frame[frame.size() / 2] ^= std::byte{0x01};
    });
    rejects([](std::span<std::byte> frame) {
        std::ranges::fill(frame, std::byte{0x00});
    });
    rejects([frameSize](std::span<std::byte> frame) {
        std::ranges::fill(frame.subspan(frameSize / 2), std::byte{0xFF});
    });

    auto cut = std::vector<std::byte>(data->encoded.begin(), data->encoded.end() - 1);
    ChunkDecoder decoder;
    std::vector<std::byte> output(minChunkSize);
    CHECK_FALSE(decoder.decode(CodecId::Brotli, cut, output));

    auto oversized = std::vector<std::byte>(minChunkSize + 1, std::byte{0});
    CHECK_FALSE(decoder.decode(CodecId::Brotli, data->encoded, oversized));
}

TEST_CASE("writer metadata records the brotli codec and level through a round trip") {
    for (archive::Preset preset : archive::allPresets) {
        auto profile = profileFor(preset);
        CHECK(parsePreset(presetName(preset)) == preset);
        auto writer = describeWriter("bale", profile, 65536, 1);
        CHECK(writer.codec == static_cast<std::uint64_t>(profile.codec));
        CHECK(writer.level == profile.level);
        CHECK(writer.preset == static_cast<std::uint64_t>(preset));
    }

    auto profile = CompressionProfile{
        .preset = std::nullopt,
        .codec = CodecId::Brotli,
        .level = 11,
    };
    auto writer = describeWriter("bale", profile, 65536, 1);
    CHECK(writer.codec == 4);
    CHECK(writer.level == 11);
    CHECK_FALSE(writer.preset);

    std::vector<std::byte> outer;
    std::vector<std::byte> scratch;
    TlvWriter encoded(outer);
    REQUIRE(encodeWriterMetadata(writer, 1, encoded, scratch));
    TlvReader reader(outer, 0);
    TlvField field;
    auto more = reader.next(field);
    REQUIRE(more);
    REQUIRE(*more);
    auto decoded = decodeWriterMetadata(field);
    REQUIRE(decoded);
    CHECK(decoded->codec == 4);
    CHECK(decoded->level == 11);
}
