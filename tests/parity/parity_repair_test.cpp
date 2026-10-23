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
#include "crypto/crypto_vectors.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::fixedOptions;
using bale::test::testUnlock;
using bale::test::testWriterSecrets;

namespace {

WriterOptions repairOptions(std::uint32_t data, std::uint32_t parity) {
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

void flipByte(const std::filesystem::path& path, std::uint64_t offset) {
    auto file = File::openReadWrite(path);
    REQUIRE(file);
    std::array<std::byte, 1> byte{};
    REQUIRE(file->readExactAt(offset, byte));
    byte[0] ^= std::byte{0xFF};
    REQUIRE(file->writeAt(offset, byte));
    REQUIRE(file->sync());
}

void zeroRange(const std::filesystem::path& path, std::uint64_t offset, std::size_t length) {
    auto file = File::openReadWrite(path);
    REQUIRE(file);
    std::vector<std::byte> zeros(length, std::byte{0});
    REQUIRE(file->writeAt(offset, zeros));
    REQUIRE(file->sync());
}

std::filesystem::path writeParityArchive(
    const bale::test::TempPath& temp,
    const std::string& name,
    std::uint32_t data,
    std::uint32_t parity,
    std::size_t blobSize = 9000
) {
    auto path = temp.path() / name;
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = Writer::create(std::move(*file), repairOptions(data, parity));
    REQUIRE(writer);
    REQUIRE(writer->addBytes("blob", deterministicBytes(blobSize, 7)));
    REQUIRE(writer->addBytes("note", bytesOf("parity repair target")));
    REQUIRE(writer->finish());
    return path;
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

void checkContentIntact(const std::filesystem::path& path) {
    auto reader = Reader::open(*File::openRead(path));
    REQUIRE(reader);
    auto report = reader->verify(VerifyMode::Content);
    REQUIRE(report);
    CHECK(report->chunksVerified == 2);
    const auto& entries = reader->manifest().entries;
    REQUIRE(entries.size() == 2);
}

}

TEST_CASE("erasures within one stripe budget repair and verify cleanly") {
    SUBCASE("single damaged byte") {
        bale::test::TempPath temp;
        {
            std::error_code ignored;
            std::filesystem::create_directories(temp.path(), ignored);
        }
        auto path = writeParityArchive(temp, "single.bale", 4, 2);
        flipByte(path, 200);
        {
            auto reader = Reader::open(*File::openRead(path));
            REQUIRE(reader);
            CHECK_FALSE(reader->verify(VerifyMode::Content));
        }
        auto outcome = runRepair(path);
        REQUIRE(outcome.generations.size() == 1);
        CHECK(outcome.generations[0].repaired);
        checkContentIntact(path);
    }

    SUBCASE("two erasures sharing stripe 0") {
        bale::test::TempPath temp;
        {
            std::error_code ignored;
            std::filesystem::create_directories(temp.path(), ignored);
        }
        auto path = writeParityArchive(temp, "multi.bale", 4, 2);
        // NOTE: S=1K, k=4: stripe 0 covers stream [0,4K); the first data payload
        // NOTE: starts at file offset 112, so two flips there share stripe 0.
        flipByte(path, 200);
        flipByte(path, 1300);
        auto outcome = runRepair(path);
        REQUIRE(outcome.generations.size() == 1);
        CHECK(outcome.generations[0].repaired);
        checkContentIntact(path);
    }
}

TEST_CASE("erasures past the budget refuse with the file untouched") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeParityArchive(temp, "over.bale", 4, 2);
    flipByte(path, 200);
    flipByte(path, 1300);
    flipByte(path, 2400);
    auto damaged = readAll(path);
    auto outcome = runRepair(path);
    REQUIRE(outcome.generations.size() == 1);
    CHECK_FALSE(outcome.generations[0].repaired);
    CHECK_FALSE(outcome.generations[0].note.empty());
    CHECK(readAll(path) == damaged);
    auto reader = Reader::open(*File::openRead(path));
    if (reader) {
        CHECK_FALSE(reader->verify(VerifyMode::Content));
    }
}

TEST_CASE("a zeroed data record recovers when it fits the stripe budget") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    // NOTE: a 1500-byte raw payload spans two 1K shards of one stripe, exactly
    // NOTE: the (4,2) budget, so wiping it whole must still recover.
    auto path = writeParityArchive(temp, "zero.bale", 4, 2, 1500);
    std::uint64_t firstPayload = 0;
    std::uint64_t firstLength = 0;
    {
        auto probe = Reader::open(*File::openRead(path));
        REQUIRE(probe);
        firstPayload = probe->index()[0].recordOffset;
        for (const auto& entry : probe->index()) {
            firstPayload = std::min(firstPayload, entry.recordOffset);
        }
        for (const auto& entry : probe->index()) {
            if (entry.recordOffset == firstPayload) {
                firstLength = entry.recordLength - recordFramingSize;
            }
        }
        REQUIRE(firstLength > 0);
        REQUIRE(firstLength <= 2048);
    }
    zeroRange(path, firstPayload + recordPrefixSize, static_cast<std::size_t>(firstLength));
    auto outcome = runRepair(path);
    CHECK(outcome.generations[0].repaired);
    checkContentIntact(path);
}

TEST_CASE("a stripped data record refuses repair past the budget") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeParityArchive(temp, "stripped.bale", 4, 2);
    std::uint64_t firstPayload = 0;
    std::uint64_t firstLength = 0;
    {
        auto probe = Reader::open(*File::openRead(path));
        REQUIRE(probe);
        firstPayload = probe->index()[0].recordOffset;
        for (const auto& entry : probe->index()) {
            firstPayload = std::min(firstPayload, entry.recordOffset);
        }
        for (const auto& entry : probe->index()) {
            if (entry.recordOffset == firstPayload) {
                firstLength = entry.recordLength - recordFramingSize;
            }
        }
        REQUIRE(firstLength > 4096);
    }
    auto damaged = readAll(path);
    zeroRange(path, firstPayload + recordPrefixSize, static_cast<std::size_t>(firstLength));
    auto zeroed = readAll(path);
    CHECK(zeroed != damaged);
    auto outcome = runRepair(path);
    CHECK_FALSE(outcome.generations[0].repaired);
    CHECK_FALSE(outcome.generations[0].note.empty());
    CHECK(readAll(path) == zeroed);
    auto reader = Reader::open(*File::openRead(path));
    if (reader) {
        CHECK_FALSE(reader->verify(VerifyMode::Content));
    }
}

TEST_CASE("footer tampering refuses repair without collateral writes") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeParityArchive(temp, "tamper.bale", 4, 2);
    auto pristine = readAll(path);
    auto size = pristine.size();
    flipByte(path, size - 20);
    auto outcome = runRepair(path);
    CHECK(outcome.generations.empty());
    CHECK(readAll(path).size() == size);
    CHECK_FALSE(readAll(path) == pristine);
    CHECK(Reader::open(*File::openRead(path)).has_value() == false);
}

TEST_CASE("repair works per generation and falls back across generations") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeParityArchive(temp, "gen.bale", 2, 1);
    {
        auto file = File::openAppend(path);
        REQUIRE(file);
        auto writer = Writer::append(std::move(*file), repairOptions(2, 1));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("second", deterministicBytes(500, 9)));
        REQUIRE(writer->finish());
    }
    // NOTE: damage a byte in the first generation's data region.
    flipByte(path, 200);
    auto outcome = runRepair(path);
    CHECK(outcome.generations.size() == 2);
    auto reader = Reader::open(*File::openRead(path));
    REQUIRE(reader);
    CHECK(reader->commit().generation == 2);
    CHECK(reader->verify(VerifyMode::Content));

    // NOTE: destroy the newest generation past its budget; the reader must
    // NOTE: still open the older generation.
    auto path2 = temp.path() / "gen2.bale";
    {
        auto bytes = readAll(path);
        auto out = File::createNew(path2);
        REQUIRE(out);
        REQUIRE(out->append(bytes));
    }
    {
        auto probe = Reader::open(*File::openRead(path2));
        REQUIRE(probe);
        REQUIRE(probe->commit().generation == 2);
        std::uint64_t manifestPayload = probe->commit().manifest.offset + recordPrefixSize;
        std::uint64_t manifestLength = probe->commit().manifest.length - recordFramingSize;
        auto bytes = readAll(path2);
        auto footer = decodeFooter(
            std::span(bytes).subspan(bytes.size() - footerSize, footerSize),
            bytes.size() - footerSize
        );
        REQUIRE(footer);
        REQUIRE(footer->generation == 2);
        zeroRange(path2, manifestPayload, static_cast<std::size_t>(manifestLength));
        zeroRange(
            path2,
            footer->commitOffset + recordPrefixSize,
            static_cast<std::size_t>(footer->commitLength - recordFramingSize)
        );
    }
    auto reader2 = Reader::open(*File::openRead(path2));
    REQUIRE(reader2);
    CHECK(reader2->commit().generation == 1);
    CHECK(reader2->verify(VerifyMode::Content));
}

TEST_CASE("compaction regenerates parity under a fresh group id") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeParityArchive(temp, "compact.bale", 4, 2);
    auto before = readAll(path);
    auto firstFooter = decodeFooter(
        std::span(before).subspan(before.size() - footerSize, footerSize),
        before.size() - footerSize
    );
    REQUIRE(firstFooter);
    REQUIRE(firstFooter->parity.present);

    auto compacted = temp.path() / "compacted.bale";
    {
        auto source = Reader::open(*File::openRead(path));
        REQUIRE(source);
        auto out = File::createNew(compacted);
        REQUIRE(out);
        auto summary = Writer::compact(std::move(*out), *source);
        REQUIRE(summary);
    }
    auto after = readAll(compacted);
    auto secondFooter = decodeFooter(
        std::span(after).subspan(after.size() - footerSize, footerSize),
        after.size() - footerSize
    );
    REQUIRE(secondFooter);
    REQUIRE(secondFooter->parity.present);
    CHECK(secondFooter->parity.groupId != firstFooter->parity.groupId);
    checkContentIntact(compacted);
}

TEST_CASE("encrypted compaction regenerates parity over ciphertext") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "enc-compact.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterOptions options = repairOptions(4, 2);
        options.experimentalEncryption = true;
        auto secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("blob", deterministicBytes(9000, 21)));
        REQUIRE(writer->finish());
    }
    auto compacted = temp.path() / "enc-compacted.bale";
    {
        auto source = Reader::openEncrypted(*File::openRead(path), ReaderOptions{}, testUnlock());
        REQUIRE(source);
        auto out = File::createNew(compacted);
        REQUIRE(out);
        auto summary = Writer::compactEncrypted(std::move(*out), *source);
        REQUIRE(summary);
    }
    auto after = readAll(compacted);
    auto footer = decodeFooter(
        std::span(after).subspan(after.size() - footerSize, footerSize),
        after.size() - footerSize
    );
    REQUIRE(footer);
    REQUIRE(footer->parity.present);
    auto reader = Reader::openEncrypted(*File::openRead(compacted), ReaderOptions{}, testUnlock());
    REQUIRE(reader);
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("signatures survive parity emission and repair") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "signed.bale";
    std::array<std::byte, 32> signer{};
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), repairOptions(2, 1));
        REQUIRE(writer);
        auto raw =
            test::hexDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        auto made = crypto::SecretBytes::make(raw.size());
        REQUIRE(made);
        crypto::SecretBytes seed(std::move(*made));
        std::ranges::copy(raw, seed.mut().begin());
        std::array<std::byte, 32> pub{};
        {
            auto derived = crypto::signPublicKeyOf(seed.bytes());
            REQUIRE(derived);
            pub = *derived;
        }
        signer = pub;
        REQUIRE(writer->addSignSeed(std::move(seed)));
        REQUIRE(writer->addBytes("blob", deterministicBytes(3000, 5)));
        REQUIRE(writer->finish());
    }
    {
        auto reader = Reader::open(*File::openRead(path));
        REQUIRE(reader);
        REQUIRE(reader->verifySignatures(std::span(&signer, 1)));
        CHECK(reader->verify(VerifyMode::Content));
    }
    flipByte(path, 200);
    auto outcome = runRepair(path);
    CHECK(outcome.generations[0].repaired);
    {
        auto reader = Reader::open(*File::openRead(path));
        REQUIRE(reader);
        CHECK(reader->verifySignatures(std::span(&signer, 1)));
        CHECK(reader->verify(VerifyMode::Content));
    }
}

TEST_CASE("repair ignores parity when the superblock does not claim it") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeParityArchive(temp, "nobit.bale", 4, 2);
    auto bytes = readAll(path);
    auto superblock = decodeSuperblock(std::span(bytes).first(superblockSize));
    REQUIRE(superblock);
    superblock->requiredFeatures &= ~parityRequiredFeature;
    auto encoded = encodeSuperblock(*superblock);
    {
        auto file = File::openReadWrite(path);
        REQUIRE(file);
        REQUIRE(file->writeAt(0, encoded));
        REQUIRE(file->sync());
    }
    auto outcome = runRepair(path);
    CHECK(outcome.generations.empty());
    CHECK_FALSE(outcome.changed);
    auto reader = Reader::open(*File::openRead(path));
    REQUIRE(reader);
    CHECK_FALSE(reader->verify(VerifyMode::Content));
}

TEST_CASE("stripping parity degrades to a plain archive that still verifies") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = writeParityArchive(temp, "strip.bale", 4, 2);
    auto bytes = readAll(path);
    auto footerOffset = bytes.size() - footerSize;
    auto footer = decodeFooter(std::span(bytes).subspan(footerOffset, footerSize), footerOffset);
    REQUIRE(footer);
    std::uint64_t firstParity = 0;
    {
        std::uint64_t position = superblockSize;
        RecordLimits limits{
            .maxPayloadLength = (std::uint64_t{256} << 20),
            .maxDecodedLength = (std::uint64_t{256} << 20),
        };
        while (position < footer->commitOffset + footer->commitLength) {
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
        firstParity = position;
        auto header = decodeRecordPrefix(
            std::span(bytes).subspan(static_cast<std::size_t>(position)),
            limits,
            position
        );
        REQUIRE(header);
        CHECK(header->type == RecordType::Parity);
    }
    // NOTE: rebuild the file without parity records and with all parity
    // NOTE: bits cleared: footer, superblock, and commit feature.
    std::vector<std::byte> stripped(
        bytes.begin(),
        bytes.begin() + static_cast<std::ptrdiff_t>(firstParity)
    );
    auto commitRecord = decodeRecord(
        std::span(bytes).subspan(
            static_cast<std::size_t>(footer->commitOffset),
            static_cast<std::size_t>(footer->commitLength)
        ),
        RecordLimits{.maxPayloadLength = 4096, .maxDecodedLength = 4096},
        footer->commitOffset
    );
    REQUIRE(commitRecord);
    auto commit = decodeCommit(commitRecord->payload, footer->commitOffset + recordPrefixSize);
    REQUIRE(commit);
    commit->requiredFeatures &= ~parityCommitFeature;
    std::vector<std::byte> commitPayload;
    REQUIRE(encodeCommit(*commit, commitPayload));
    auto commitDigest = Blake3::of(HashDomain::Commit, commitPayload);
    auto prefix = encodeRecordPrefix(
        RecordHeader{
            .type = RecordType::Commit,
            .flags = commitRecord->header.flags,
            .payloadLength = commitPayload.size(),
            .decodedLength = commitPayload.size(),
            .sequence = commitRecord->header.sequence,
            .codec = CodecId::Raw,
        }
    );
    auto trailer = encodeRecordTrailer(Crc32c::of(commitPayload));
    std::uint64_t commitLength = recordFramingSize + commitPayload.size();
    REQUIRE(footer->commitLength == commitLength);
    std::ranges::copy(prefix, stripped.begin() + static_cast<std::ptrdiff_t>(footer->commitOffset));
    std::ranges::copy(
        commitPayload,
        stripped.begin() + static_cast<std::ptrdiff_t>(footer->commitOffset + recordPrefixSize)
    );
    std::ranges::copy(
        trailer,
        stripped.begin() +
            static_cast<std::ptrdiff_t>(
                footer->commitOffset + recordPrefixSize + commitPayload.size()
            )
    );
    Footer strippedFooter = *footer;
    strippedFooter.commitDigest = commitDigest;
    strippedFooter.parity = ParityDescriptor{};
    auto footerBytes = encodeFooter(strippedFooter);
    stripped.insert(stripped.end(), footerBytes.begin(), footerBytes.end());
    auto superblock = decodeSuperblock(std::span(stripped).first(superblockSize));
    REQUIRE(superblock);
    superblock->requiredFeatures &= ~parityRequiredFeature;
    auto superBytes = encodeSuperblock(*superblock);
    std::ranges::copy(superBytes, stripped.begin());

    auto strippedPath = temp.path() / "stripped.bale";
    {
        auto out = File::createNew(strippedPath);
        REQUIRE(out);
        REQUIRE(out->append(stripped));
    }
    auto reader = Reader::open(*File::openRead(strippedPath));
    REQUIRE(reader);
    CHECK_FALSE(reader->parity().present);
    CHECK(reader->verify(VerifyMode::Content));
}

TEST_CASE("encrypted generations repair ciphertext with key-gated release") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "enc.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterOptions options = repairOptions(4, 2);
        options.experimentalEncryption = true;
        auto secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("blob", deterministicBytes(9000, 21)));
        REQUIRE(writer->finish());
    }
    auto unlock = testUnlock();
    {
        auto reader = Reader::openEncrypted(*File::openRead(path), ReaderOptions{}, testUnlock());
        REQUIRE(reader);
        CHECK(reader->verify(VerifyMode::Content));
    }
    flipByte(path, 300);
    {
        auto reader = Reader::openEncrypted(*File::openRead(path), ReaderOptions{}, testUnlock());
        REQUIRE(reader);
        CHECK_FALSE(reader->verify(VerifyMode::Content));
    }
    RepairKeys keys;
    {
        auto file = File::openRead(path);
        REQUIRE(file);
        auto size = file->size();
        REQUIRE(size);
        auto found = collectDataKeys(*file, *size, unlock, Limits{});
        REQUIRE(found);
        REQUIRE_FALSE(found->empty());
        keys.byEpoch = std::move(*found);
        std::array<std::byte, superblockSize> block{};
        REQUIRE(file->readExactAt(0, block));
        auto superblock = decodeSuperblock(block);
        REQUIRE(superblock);
        keys.archiveId = superblock->archiveId;
    }
    auto outcome = runRepair(path, &keys);
    REQUIRE(outcome.generations.size() == 1);
    CHECK(outcome.generations[0].repaired);
    {
        auto reader = Reader::openEncrypted(*File::openRead(path), ReaderOptions{}, testUnlock());
        REQUIRE(reader);
        CHECK(reader->verify(VerifyMode::Content));
    }
}
