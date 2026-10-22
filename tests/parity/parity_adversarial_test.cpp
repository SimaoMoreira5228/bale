#include "archive/encrypted.hpp"
#include "archive/parity.hpp"
#include "archive/parity_repair.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"
#include "io/file.hpp"

#include "archive/archive_fixture.hpp"
#include "archive/encrypted_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::fixedOptions;
using bale::test::testKdf;
using bale::test::testUnlock;
using bale::test::testWriterSecrets;

namespace {

void flipByte(const std::filesystem::path& path, std::uint64_t offset) {
    auto file = File::openReadWrite(path);
    REQUIRE(file);
    std::array<std::byte, 1> byte{};
    REQUIRE(file->readExactAt(offset, byte));
    byte[0] ^= std::byte{0xFF};
    REQUIRE(file->writeAt(offset, byte));
    REQUIRE(file->sync());
}

WriterOptions hostileOptions(std::uint32_t data, std::uint32_t parity) {
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
    auto file = File::openRead(path);
    REQUIRE(file);
    auto size = file->size();
    REQUIRE(size);
    std::vector<std::byte> out(static_cast<std::size_t>(*size));
    REQUIRE(file->readExactAt(0, out));
    return out;
}

std::filesystem::path writeHostileArchive(
    const bale::test::TempPath& temp,
    const std::string& name,
    std::uint32_t data,
    std::uint32_t parity
) {
    auto path = temp.path() / name;
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = Writer::create(std::move(*file), hostileOptions(data, parity));
    REQUIRE(writer);
    REQUIRE(writer->addBytes("blob", deterministicBytes(9000, 7)));
    REQUIRE(writer->finish());
    return path;
}

std::uint64_t firstParityOffset(const std::vector<std::byte>& bytes) {
    auto footer = decodeFooter(
        std::span(bytes).subspan(bytes.size() - footerSize, footerSize),
        bytes.size() - footerSize
    );
    REQUIRE(footer);
    std::uint64_t position = superblockSize;
    RecordLimits limits{
        .maxPayloadLength = (std::uint64_t{256} << 20),
        .maxDecodedLength = (std::uint64_t{256} << 20),
    };
    std::uint64_t commitEnd = footer->commitOffset + footer->commitLength;
    while (position < commitEnd) {
        auto header = decodeRecordPrefix(
            std::span(bytes).subspan(static_cast<std::size_t>(position)),
            limits,
            position
        );
        REQUIRE(header);
        auto size = recordSize(header->payloadLength);
        REQUIRE(size);
        position += *size;
    }
    return position;
}

void patchBytes(
    const std::filesystem::path& path,
    std::uint64_t offset,
    std::span<const std::byte> bytes
) {
    auto file = File::openReadWrite(path);
    REQUIRE(file);
    REQUIRE(file->writeAt(offset, bytes));
    REQUIRE(file->sync());
}

RepairOutcome runRepair(const std::filesystem::path& path, const RepairKeys* keys = nullptr) {
    auto file = File::openReadWrite(path);
    REQUIRE(file);
    auto size = file->size();
    REQUIRE(size);
    std::array<std::byte, superblockSize> block{};
    REQUIRE(file->readExactAt(0, block));
    auto superblock = decodeSuperblock(block);
    REQUIRE(superblock);
    auto outcome = repairParityGenerations(*file, *size, *superblock, Limits{}, keys);
    REQUIRE(outcome);
    return *outcome;
}

}

TEST_CASE("a forged parity record cannot launder bytes past the content hash") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    // NOTE: (1,1) leaves a single parity record per stripe: forging it is
    // NOTE: unanimous, so only the record-layer hash can stop the lie.
    auto path = writeHostileArchive(temp, "forge.bale", 1, 1);
    // NOTE: corrupt one data byte, then forge the stripe-0 parity record with
    // NOTE: a self-consistent table and shard for the corrupted stream.
    auto forged = readAll(path);
    forged[200] = static_cast<std::byte>(forged[200] ^ std::byte{0xFF});
    std::uint64_t parityAt = firstParityOffset(forged);
    {
        RecordLimits limits{
            .maxPayloadLength = maxParityRecordPayload,
            .maxDecodedLength = maxParityRecordPayload,
        };
        auto header = decodeRecordPrefix(
            std::span(forged).subspan(static_cast<std::size_t>(parityAt)),
            limits,
            parityAt
        );
        REQUIRE(header);
        auto size = recordSize(header->payloadLength);
        REQUIRE(size);
        auto record = decodeRecord(
            std::span(forged)
                .subspan(static_cast<std::size_t>(parityAt), static_cast<std::size_t>(*size)),
            limits,
            parityAt
        );
        REQUIRE(record);
        auto parsed = decodeParityRecord(record->payload, parityAt + recordPrefixSize);
        REQUIRE(parsed);
        REQUIRE(parsed->stripeIndex == 0);
        std::uint64_t headerLength = parityHeaderLength(parsed->dataShards + parsed->parityShards);
        // NOTE: flip a shard byte and re-crc the table entry so framing stays
        // NOTE: valid: the record now vouches for corrupted bytes.
        std::size_t shardByte =
            static_cast<std::size_t>(parityAt + recordPrefixSize + headerLength + 3);
        forged[shardByte] = static_cast<std::byte>(forged[shardByte] ^ std::byte{0x01});
        std::vector<std::byte> shard(
            forged.begin() + static_cast<std::ptrdiff_t>(shardByte - 3),
            forged.begin() + static_cast<std::ptrdiff_t>(shardByte - 3 + parsed->shardBytes)
        );
        std::uint32_t fixed = Crc32c::of(shard);
        std::size_t tableByte = static_cast<std::size_t>(
            parityAt + recordPrefixSize + 60 + static_cast<std::uint64_t>(parsed->shardIndex) * 4
        );
        storeLe(forged.data() + tableByte, fixed);
        std::span<std::byte> payload = std::span(forged).subspan(
            static_cast<std::size_t>(parityAt + recordPrefixSize),
            static_cast<std::size_t>(header->payloadLength)
        );
        std::array<std::byte, recordTrailerSize> trailer{};
        storeLe(trailer.data(), Crc32c::of(payload));
        std::ranges::copy(recordEndMarker, trailer.begin() + 4);
        std::ranges::copy(
            trailer,
            forged.begin() +
                static_cast<std::ptrdiff_t>(parityAt + recordPrefixSize + header->payloadLength)
        );
    }
    patchBytes(path, 0, forged);
    auto damaged = readAll(path);
    auto outcome = runRepair(path);
    CHECK_FALSE(outcome.generations[0].repaired);
    CHECK_FALSE(outcome.generations[0].note.empty());
    CHECK(readAll(path) == damaged);
    auto reader = Reader::open(*File::openRead(path));
    REQUIRE(reader);
    CHECK_FALSE(reader->verify(VerifyMode::Content));
}

TEST_CASE("truncated and corrupt parity records degrade instead of killing repair") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeHostileArchive(temp, "degrade.bale", 4, 2);
    auto pristine = readAll(path);
    std::uint64_t parityAt = firstParityOffset(pristine);
    // NOTE: damage a data byte in stripe 0 and wipe one stripe-0 parity record
    // NOTE: payload: the remaining three records still cover the budget.
    pristine[200] = static_cast<std::byte>(pristine[200] ^ std::byte{0xFF});
    {
        RecordLimits limits{
            .maxPayloadLength = maxParityRecordPayload,
            .maxDecodedLength = maxParityRecordPayload,
        };
        auto header = decodeRecordPrefix(
            std::span(pristine).subspan(static_cast<std::size_t>(parityAt)),
            limits,
            parityAt
        );
        REQUIRE(header);
        REQUIRE(header->type == RecordType::Parity);
        std::fill(
            pristine.begin() + static_cast<std::ptrdiff_t>(parityAt + recordPrefixSize),
            pristine.begin() +
                static_cast<std::ptrdiff_t>(parityAt + recordPrefixSize + header->payloadLength),
            std::byte{0xCC}
        );
    }
    patchBytes(path, 200, std::span(pristine).subspan(200, 1));
    patchBytes(
        path,
        parityAt + recordPrefixSize,
        std::span(pristine).subspan(static_cast<std::size_t>(parityAt + recordPrefixSize), 64)
    );
    auto outcome = runRepair(path);
    CHECK(outcome.generations[0].repaired);
    auto reader = Reader::open(*File::openRead(path));
    REQUIRE(reader);
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("parity records bound to another generation are ignored") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeHostileArchive(temp, "rebind.bale", 4, 2);
    auto pristine = readAll(path);
    std::uint64_t parityAt = firstParityOffset(pristine);
    pristine[200] = static_cast<std::byte>(pristine[200] ^ std::byte{0xFF});
    // NOTE: rewrite the first parity record's generation field with a valid
    // NOTE: trailer: repair must treat it as foreign, not as evidence.
    {
        RecordLimits limits{
            .maxPayloadLength = maxParityRecordPayload,
            .maxDecodedLength = maxParityRecordPayload,
        };
        auto header = decodeRecordPrefix(
            std::span(pristine).subspan(static_cast<std::size_t>(parityAt)),
            limits,
            parityAt
        );
        REQUIRE(header);
        storeLe(pristine.data() + parityAt + recordPrefixSize + 12, std::uint64_t{99});
        std::span<std::byte> payload = std::span(pristine).subspan(
            static_cast<std::size_t>(parityAt + recordPrefixSize),
            static_cast<std::size_t>(header->payloadLength)
        );
        std::array<std::byte, recordTrailerSize> trailer{};
        storeLe(trailer.data(), Crc32c::of(payload));
        std::ranges::copy(recordEndMarker, trailer.begin() + 4);
        std::ranges::copy(
            trailer,
            pristine.begin() +
                static_cast<std::ptrdiff_t>(parityAt + recordPrefixSize + header->payloadLength)
        );
    }
    patchBytes(path, 0, std::span(pristine).first(pristine.size()));
    auto outcome = runRepair(path);
    CHECK(outcome.generations[0].repaired);
    auto reader = Reader::open(*File::openRead(path));
    REQUIRE(reader);
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("shard length mismatches and absurd descriptors fail closed") {
    CHECK_FALSE(decodeParityRecord(std::vector<std::byte>(60, std::byte{0}), 0));
    ParityHeader header;
    header.groupId = 1;
    header.generation = 1;
    header.stripeIndex = 0;
    header.shardIndex = 1;
    header.dataShards = 1;
    header.parityShards = 1;
    header.shardBytes = (std::uint32_t{64} << 20) + 1;
    header.stripeCount = 1;
    header.streamLength = 1;
    header.crc.assign(2, 0);
    std::vector<std::byte> out;
    CHECK_FALSE(encodeParityRecord(header, std::vector<std::byte>(16), out));

    Footer footer;
    footer.parity.present = true;
    footer.parity.dataShards = 255;
    footer.parity.parityShards = 1;
    footer.parity.shardBytes = (std::uint32_t{256} << 20);
    footer.parity.stripeCount = std::uint64_t{1} << 60;
    footer.parity.groupId = 9;
    footer.commitOffset = superblockSize;
    footer.commitLength = recordFramingSize;
    footer.generation = 1;
    auto encoded = encodeFooter(footer);
    auto decoded = decodeFooter(encoded, superblockSize + recordFramingSize);
    REQUIRE(decoded);
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "absurd.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        std::array<std::byte, superblockSize> superblock{};
        Superblock plain;
        plain.requiredFeatures = parityRequiredFeature;
        auto empty = encodeSuperblock(plain);
        std::ranges::copy(empty, superblock.begin());
        REQUIRE(file->append(superblock));
        std::vector<std::byte> gap(recordFramingSize, std::byte{0});
        REQUIRE(file->append(gap));
        REQUIRE(file->append(encoded));
    }
    auto outcome = runRepair(path);
    CHECK(outcome.generations.size() == 1);
    CHECK_FALSE(outcome.generations[0].repaired);
    CHECK_FALSE(outcome.generations[0].note.empty());
}

TEST_CASE("parity repair with the wrong key refuses instead of releasing bytes") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "wrongkey.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterOptions options = hostileOptions(4, 2);
        options.experimentalEncryption = true;
        auto secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("blob", deterministicBytes(9000, 21)));
        REQUIRE(writer->finish());
    }
    flipByte(path, 300);
    WriterSecrets wrongSecrets;
    wrongSecrets.hasPassword = true;
    auto made = crypto::SecretBytes::make(7);
    REQUIRE(made);
    wrongSecrets.password = std::move(*made);
    std::string_view pw = "wrong-p";
    std::ranges::copy(std::as_bytes(std::span(pw)), wrongSecrets.password.mut().begin());
    wrongSecrets.kdf = testKdf();
    ReaderUnlock wrongUnlock;
    wrongUnlock.hasPassword = true;
    auto madeUnlock = crypto::SecretBytes::make(7);
    REQUIRE(madeUnlock);
    wrongUnlock.password = std::move(*madeUnlock);
    std::ranges::copy(std::as_bytes(std::span(pw)), wrongUnlock.password.mut().begin());
    {
        auto file = File::openReadWrite(path);
        REQUIRE(file);
        auto size = file->size();
        REQUIRE(size);
        auto found = collectDataKeys(*file, *size, wrongUnlock, Limits{});
        REQUIRE(found);
        CHECK(found->empty());
    }
    auto outcome = runRepair(path, nullptr);
    CHECK(outcome.generations.size() == 1);
    CHECK_FALSE(outcome.generations[0].repaired);
    CHECK_FALSE(
        Reader::openEncrypted(*File::openRead(path), ReaderOptions{}, testUnlock())
            ->verify(VerifyMode::Content)
    );
}
