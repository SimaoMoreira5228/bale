#include "archive/parity.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"
#include "io/file.hpp"
#include "parity/reed_solomon.hpp"

#include "archive/archive_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <span>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::parity::ReedSolomon;
using bale::test::bytesOf;
using bale::test::fixedOptions;

namespace {

WriterOptions parityOptions(std::uint32_t data, std::uint32_t parity) {
    WriterOptions options = fixedOptions();
    options.workers = 1;
    options.compression.codec = CodecId::Raw;
    options.compression.level = 0;
    options.parity.enabled = true;
    options.parity.dataShards = data;
    options.parity.parityShards = parity;
    options.parity.shardBytes = 1024;
    return options;
}

std::vector<std::byte> deterministicBytes(std::size_t size, std::uint32_t seed = 0x1234) {
    std::vector<std::byte> out(size);
    std::uint32_t state = seed;
    for (auto& cell : out) {
        state = state * 1664525 + 1013904223;
        cell = static_cast<std::byte>(state >> 24);
    }
    return out;
}

std::vector<std::byte> readAll(const std::filesystem::path& path) {
    std::vector<std::byte> out;
    auto file = File::openRead(path);
    REQUIRE(file);
    auto size = file->size();
    REQUIRE(size);
    out.resize(static_cast<std::size_t>(*size));
    REQUIRE(file->readExactAt(0, out));
    return out;
}

struct ParityRecordView {
    std::uint64_t fileOffset = 0;
    ParityHeader header;
    std::vector<std::byte> shard;
};

std::vector<ParityRecordView> collectParityRecords(const std::vector<std::byte>& file) {
    std::vector<ParityRecordView> out;
    std::uint64_t position = superblockSize;
    RecordLimits limits{
        .maxPayloadLength = maxParityRecordPayload,
        .maxDecodedLength = maxParityRecordPayload,
    };
    while (position + recordFramingSize <= file.size()) {
        if (std::ranges::equal(
                std::span(file).subspan(static_cast<std::size_t>(position), 8),
                footerMagic
            )) {
            break;
        }
        auto header = decodeRecordPrefix(
            std::span(file).subspan(static_cast<std::size_t>(position)),
            limits,
            position
        );
        REQUIRE(header);
        auto size = recordSize(header->payloadLength);
        REQUIRE(size);
        REQUIRE(*size <= file.size() - position);
        if (header->type == RecordType::Parity) {
            auto record = decodeRecord(
                std::span(file)
                    .subspan(static_cast<std::size_t>(position), static_cast<std::size_t>(*size)),
                limits,
                position
            );
            REQUIRE(record);
            auto parsed = decodeParityRecord(record->payload, position + recordPrefixSize);
            REQUIRE(parsed);
            std::uint64_t headerLength =
                parityHeaderLength(parsed->dataShards + parsed->parityShards);
            ParityRecordView view;
            view.fileOffset = position;
            view.header = *parsed;
            view.shard.assign(
                record->payload.begin() + static_cast<std::ptrdiff_t>(headerLength),
                record->payload.end()
            );
            out.push_back(std::move(view));
        }
        position += *size;
    }
    return out;
}

void checkStoredParityMatchesMath(
    const std::vector<std::byte>& file,
    std::uint32_t dataShards,
    std::uint32_t parityShards
) {
    auto records = collectParityRecords(file);
    REQUIRE_FALSE(records.empty());

    auto footer = decodeFooter(
        std::span(file).subspan(file.size() - footerSize, footerSize),
        file.size() - footerSize
    );
    REQUIRE(footer);
    auto commitBytes = std::span(file).subspan(
        static_cast<std::size_t>(footer->commitOffset),
        static_cast<std::size_t>(footer->commitLength)
    );
    RecordLimits commitLimits{
        .maxPayloadLength = 4096,
        .maxDecodedLength = 4096,
    };
    auto commitRecord = decodeRecord(commitBytes, commitLimits, footer->commitOffset);
    REQUIRE(commitRecord);
    auto commit = decodeCommit(commitRecord->payload, footer->commitOffset + recordPrefixSize);
    REQUIRE(commit);

    struct Range {
        std::uint64_t fileOffset = 0;
        std::uint64_t length = 0;
    };
    std::vector<Range> dataRanges;
    RecordLimits walkLimits{
        .maxPayloadLength = (std::uint64_t{256} << 20),
        .maxDecodedLength = (std::uint64_t{256} << 20),
    };
    std::uint64_t position = superblockSize;
    while (position < footer->commitOffset) {
        auto header = decodeRecordPrefix(
            std::span(file).subspan(static_cast<std::size_t>(position)),
            walkLimits,
            position
        );
        REQUIRE(header);
        auto size = recordSize(header->payloadLength);
        REQUIRE(size);
        if (header->type == RecordType::Data) {
            dataRanges.push_back(
                Range{
                    .fileOffset = position + recordPrefixSize,
                    .length = header->payloadLength,
                }
            );
        }
        position += *size;
    }
    auto payloadRange = [&](const RecordReference& reference) {
        return Range{
            .fileOffset = reference.offset + recordPrefixSize,
            .length = reference.length - recordFramingSize,
        };
    };
    std::vector<Range> segments = dataRanges;
    segments.push_back(payloadRange(commit->index));
    segments.push_back(payloadRange(commit->manifest));
    segments.push_back(
        Range{
            .fileOffset = footer->commitOffset + recordPrefixSize,
            .length = footer->commitLength - recordFramingSize,
        }
    );
    auto readStream = [&](std::uint64_t at) {
        std::uint64_t cursor = 0;
        for (const auto& segment : segments) {
            if (at >= cursor && at < cursor + segment.length) {
                return file[static_cast<std::size_t>(segment.fileOffset + (at - cursor))];
            }
            cursor += segment.length;
        }
        return std::byte{0};
    };

    auto coder = ReedSolomon::make(dataShards, parityShards);
    REQUIRE(coder);

    std::map<std::uint64_t, std::vector<const ParityRecordView*>> byStripe;
    for (const auto& record : records) {
        CHECK(record.header.dataShards == dataShards);
        CHECK(record.header.parityShards == parityShards);
        byStripe[record.header.stripeIndex].push_back(&record);
    }
    for (const auto& [stripe, refs] : byStripe) {
        CHECK(refs.size() == parityShards);
        const auto& table = refs.front()->header.crc;
        for (const auto* ref : refs) {
            CHECK(ref->header.crc == table);
        }
        std::uint32_t shardBytes = refs.front()->header.shardBytes;
        std::uint64_t stripeStart = stripe * static_cast<std::uint64_t>(dataShards) * shardBytes;
        std::uint64_t streamLength = refs.front()->header.streamLength;
        std::vector<std::vector<std::byte>> data(dataShards, std::vector<std::byte>(shardBytes));
        for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
            std::uint64_t shardOffset =
                stripeStart + static_cast<std::uint64_t>(shard) * shardBytes;
            for (std::uint32_t byte = 0; byte < shardBytes; ++byte) {
                std::uint64_t at = shardOffset + byte;
                data[shard][byte] = at < streamLength ? readStream(at) : std::byte{0};
            }
        }
        std::vector<std::vector<std::byte>> parity(
            parityShards,
            std::vector<std::byte>(shardBytes)
        );
        std::vector<std::span<const std::byte>> dataViews(dataShards);
        std::vector<std::span<std::byte>> parityViews(parityShards);
        for (std::uint32_t shard = 0; shard < dataShards; ++shard) {
            dataViews[shard] = data[shard];
        }
        for (std::uint32_t shard = 0; shard < parityShards; ++shard) {
            parityViews[shard] = parity[shard];
        }
        REQUIRE(coder->encode(dataViews, parityViews));
        for (const auto* ref : refs) {
            std::uint32_t parityIndex = ref->header.shardIndex - dataShards;
            REQUIRE(parityIndex < parityShards);
            CHECK(parity[parityIndex] == ref->shard);
        }
    }
}

}

TEST_CASE("parity round-trips content at every supported operating point") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    for (auto [dataShards, parityShards] : {std::pair{1U, 1U}, {4U, 2U}, {10U, 4U}, {17U, 3U}}) {
        CAPTURE(dataShards);
        CAPTURE(parityShards);
        auto path = temp.path() /
            ("parity_" + std::to_string(dataShards) + "_" + std::to_string(parityShards) + ".bale");
        auto payload = deterministicBytes(9000);
        {
            auto file = File::createNew(path);
            REQUIRE(file);
            auto writer = Writer::create(std::move(*file), parityOptions(dataShards, parityShards));
            REQUIRE(writer);
            REQUIRE(writer->addBytes("blob", payload));
            REQUIRE(writer->addBytes("small", bytesOf("hello parity")));
            auto summary = writer->finish();
            REQUIRE(summary);
        }
        auto file = readAll(path);
        auto records = collectParityRecords(file);
        auto footer = decodeFooter(
            std::span(file).subspan(file.size() - footerSize, footerSize),
            file.size() - footerSize
        );
        REQUIRE(footer);
        REQUIRE(footer->parity.present);
        CHECK(footer->parity.dataShards == dataShards);
        CHECK(footer->parity.parityShards == parityShards);
        CHECK(records.size() == footer->parity.stripeCount * parityShards);

        auto reader = Reader::open(*File::openRead(path));
        REQUIRE(reader);
        auto report = reader->verify(VerifyMode::Content);
        REQUIRE(report);
        CHECK(report->chunksVerified == 2);
        const auto& entries = reader->manifest().entries;
        REQUIRE(entries.size() == 2);
        std::string blob;
        std::string small;
        for (const auto& entry : entries) {
            if (entry.path == "blob") {
                blob = bale::test::contents(*reader, entry);
            } else if (entry.path == "small") {
                small = bale::test::contents(*reader, entry);
            }
        }
        CHECK(small == "hello parity");
        CHECK(blob == std::string(reinterpret_cast<const char*>(payload.data()), payload.size()));
    }
}

TEST_CASE("stored parity shards equal an independent Cauchy encode of the stream") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "math.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), parityOptions(4, 2));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("blob", deterministicBytes(9000, 77)));
        REQUIRE(writer->finish());
    }
    auto file = readAll(path);
    checkStoredParityMatchesMath(file, 4, 2);
}

TEST_CASE("parity writer validates its policy and binds old-reader refusal bits") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto bad = parityOptions(0, 2);
    {
        auto file = File::createNew(temp.path() / "bad.bale");
        REQUIRE(file);
        CHECK_FALSE(Writer::create(std::move(*file), bad));
    }
    auto tooMany = parityOptions(200, 100);
    {
        auto file = File::createNew(temp.path() / "many.bale");
        REQUIRE(file);
        CHECK_FALSE(Writer::create(std::move(*file), tooMany));
    }
    auto path = temp.path() / "bits.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), parityOptions(2, 1));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a", bytesOf("x")));
        REQUIRE(writer->finish());
    }
    auto file = readAll(path);
    Superblock superblock;
    {
        auto decoded = decodeSuperblock(std::span(file).first(superblockSize));
        REQUIRE(decoded);
        superblock = *decoded;
    }
    CHECK((superblock.requiredFeatures & parityRequiredFeature) != 0);

    auto reader = Reader::open(*File::openRead(path));
    REQUIRE(reader);
    CHECK((reader->commit().requiredFeatures & parityCommitFeature) != 0);
    CHECK(reader->parity().present);
}

TEST_CASE("append without parity leaves earlier parity generations untouched") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "append.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), parityOptions(2, 1));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a", deterministicBytes(3000, 1)));
        REQUIRE(writer->finish());
    }
    auto before = readAll(path);
    {
        auto file = File::openAppend(path);
        REQUIRE(file);
        WriterOptions plain = fixedOptions();
        plain.workers = 1;
        plain.compression.codec = CodecId::Raw;
        auto writer = Writer::append(std::move(*file), plain);
        REQUIRE(writer);
        REQUIRE(writer->addBytes("b", deterministicBytes(100, 2)));
        REQUIRE(writer->finish());
    }
    auto after = readAll(path);
    CHECK(
        std::ranges::equal(
            std::span(before).first(before.size() - footerSize),
            std::span(after).first(before.size() - footerSize)
        )
    );
    auto reader = Reader::open(*File::openRead(path));
    REQUIRE(reader);
    CHECK(reader->commit().generation == 2);
    CHECK_FALSE(reader->parity().present);
    CHECK(reader->verify(VerifyMode::Content));
}
