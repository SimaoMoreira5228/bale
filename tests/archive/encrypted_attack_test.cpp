#include "archive/encrypted.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "crypto/crypto.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"

#include "archive/archive_fixture.hpp"
#include "archive/encrypted_fixture.hpp"

#include <doctest/doctest.h>
#include <sodium/crypto_pwhash_argon2id.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <set>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::fixedOptions;
using bale::test::tempArchive;
using bale::test::testKdf;
using bale::test::testUnlock;
using bale::test::testWriterSecrets;

// NOTE: the red-team findings, pinned. Each case below locks in one adversarial-review
// item: the fixed behavior for the two exploits, the documented properties for rollback
// and the error oracle, and the coverage the review left open (nonces, AAD gaps,
// downgrade mixing, compaction). Builder feature tests live in encrypted_test.cpp.

namespace {

void writeBytes(const std::filesystem::path& path, const std::vector<std::byte>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    REQUIRE(out);
    out.write(
        reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size())
    );
    REQUIRE(out);
}

struct ScannedRecord {
    std::uint64_t offset = 0;
    RecordType type = RecordType::Data;
    std::uint16_t flags = 0;
    std::uint64_t payloadLength = 0;
    std::vector<std::byte> payload;
};

// NOTE: minimal framing scanner for tests: walks records until the first footer, like the
// reader's own scan but returning offsets so tests can mutate precise bytes.
std::vector<ScannedRecord> scanAllRecords(const std::vector<std::byte>& bytes) {
    std::vector<ScannedRecord> out;
    std::uint64_t position = superblockSize;
    while (position + recordFramingSize <= bytes.size()) {
        auto prefix =
            std::span(bytes).subspan(static_cast<std::size_t>(position), recordPrefixSize);
        if (!std::ranges::equal(prefix.first<4>(), recordMagic)) {
            break;
        }
        std::uint64_t payloadLength = loadLe<std::uint64_t>(prefix.data() + 8);
        std::uint64_t size = payloadLength + recordFramingSize;
        REQUIRE(size <= bytes.size() - position);
        ScannedRecord record;
        record.offset = position;
        record.type = static_cast<RecordType>(loadLe<std::uint16_t>(prefix.data() + 4));
        record.flags = loadLe<std::uint16_t>(prefix.data() + 6);
        record.payloadLength = payloadLength;
        auto payload = std::span(bytes).subspan(
            static_cast<std::size_t>(position + recordPrefixSize),
            static_cast<std::size_t>(payloadLength)
        );
        record.payload.assign(payload.begin(), payload.end());
        out.push_back(std::move(record));
        position += size;
        if (position + footerSize <= bytes.size() &&
            std::ranges::equal(
                std::span(bytes).subspan(static_cast<std::size_t>(position), 8),
                std::span(footerMagic).first<8>()
            )) {
            break;
        }
    }
    return out;
}

const ScannedRecord* findFirstRecord(const std::vector<ScannedRecord>& records, RecordType type) {
    for (const auto& record : records) {
        if (record.type == type) {
            return &record;
        }
    }
    return nullptr;
}

// NOTE: recompute framing checksums after a surgical mutation so the failure under test comes
// from the semantic or cryptographic gate, not the CRC layer.
void repairPrefixCrc(std::vector<std::byte>& bytes, std::uint64_t recordOffset) {
    auto prefix =
        std::span(bytes).subspan(static_cast<std::size_t>(recordOffset), recordPrefixSize);
    std::fill_n(prefix.begin() + 36, 4, std::byte{0});
    std::array<std::byte, recordPrefixSize> view{};
    std::ranges::copy(prefix, view.begin());
    storeLe(prefix.data() + 36, Crc32c::of(view));
}

void repairPayloadCrc(std::vector<std::byte>& bytes, const ScannedRecord& record) {
    auto payload = std::span(bytes).subspan(
        static_cast<std::size_t>(record.offset + recordPrefixSize),
        static_cast<std::size_t>(record.payloadLength)
    );
    auto trailer = std::span(bytes).subspan(
        static_cast<std::size_t>(record.offset + recordPrefixSize + record.payloadLength),
        recordTrailerSize
    );
    storeLe(trailer.data(), Crc32c::of(payload));
}

}

TEST_CASE("relabelled keyslot epoch does not unwrap") {
    auto dataKey = crypto::makeKey();
    REQUIRE(dataKey);
    std::vector<std::byte> password{std::byte{'p'}, std::byte{'w'}};
    auto slot = crypto::wrapPasswordKey(dataKey->bytes(), password, testKdf(), 1);
    REQUIRE(slot);

    Keyslot first;
    first.epoch = 1;
    first.kind = SlotKind::Password;
    first.salt = slot->salt;
    first.opslimit = slot->opslimit;
    first.memlimitBytes = slot->memlimitBytes;
    first.nonce = slot->nonce;
    first.wrapped = slot->wrapped;

    Keyslot second = first;
    second.epoch = 2;

    std::vector<std::byte> firstBytes;
    REQUIRE(encodeKeyslot(first, firstBytes));
    std::vector<std::byte> secondBytes;
    REQUIRE(encodeKeyslot(second, secondBytes));
    auto decodedFirst = decodeKeyslot(firstBytes, 0);
    REQUIRE(decodedFirst);
    auto decodedSecond = decodeKeyslot(secondBytes, 0);
    REQUIRE(decodedSecond);

    auto toPassword = [](const Keyslot& decoded) {
        crypto::PasswordSlot out;
        out.epoch = decoded.epoch;
        out.salt = decoded.salt;
        out.opslimit = decoded.opslimit;
        out.memlimitBytes = decoded.memlimitBytes;
        out.nonce = decoded.nonce;
        out.wrapped = decoded.wrapped;
        return out;
    };
    // NOTE: the epoch rides in the slot seal AAD, so the relabelled copy cannot unwrap even
    // though every other byte is identical; the commit epoch check stays as a second gate.
    auto good = crypto::unwrapPasswordKey(toPassword(*decodedFirst), password);
    REQUIRE(good);
    CHECK(std::ranges::equal(good->bytes(), dataKey->bytes()));
    auto bad = crypto::unwrapPasswordKey(toPassword(*decodedSecond), password);
    REQUIRE_FALSE(bad);
    CHECK(bad.error().kind == ErrorKind::Integrity);
}

TEST_CASE("crafted slot KDF params are rejected before any KDF use") {
    auto decodedWith = [](std::uint64_t ops, std::uint64_t mem) {
        Keyslot slot;
        slot.epoch = 1;
        slot.kind = SlotKind::Password;
        slot.salt.fill(std::byte{0xAA});
        slot.opslimit = ops;
        slot.memlimitBytes = static_cast<std::size_t>(mem);
        slot.nonce.fill(std::byte{0xBB});
        slot.wrapped = std::vector<std::byte>(crypto::keySize + crypto::tagSize, std::byte{0xCC});
        std::vector<std::byte> encoded;
        REQUIRE(encodeKeyslot(slot, encoded));
        return decodeKeyslot(encoded, 0);
    };
    // NOTE: libsodium-range maxima fail at the TLV layer, before any KDF allocation.
    auto huge =
        decodedWith(crypto_pwhash_argon2id_OPSLIMIT_MAX, crypto_pwhash_argon2id_MEMLIMIT_MAX);
    REQUIRE_FALSE(huge);
    CHECK(huge.error().kind == ErrorKind::LimitExceeded);
    auto overOps = decodedWith(crypto::maxSlotOpslimit + 1, 8192);
    REQUIRE_FALSE(overOps);
    CHECK(overOps.error().kind == ErrorKind::LimitExceeded);
    auto overMem = decodedWith(1, std::uint64_t{crypto::maxSlotMemlimitBytes} + 1);
    REQUIRE_FALSE(overMem);
    CHECK(overMem.error().kind == ErrorKind::LimitExceeded);
    // NOTE: foreseeable profiles still decode: the ceiling sits at SENSITIVE, MODERATE below it.
    CHECK(decodedWith(
        crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE,
        crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE
    ));
    CHECK(decodedWith(
        crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
        crypto_pwhash_argon2id_MEMLIMIT_MODERATE
    ));
    CHECK(decodedWith(1, 8192));
}

TEST_CASE("keyslot count is bounded during collection") {
    auto path = tempArchive("bale-enc-slotcount.bale");
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterSecrets first = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(first));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("v1")));
        REQUIRE(writer->finish());
    }
    for (std::uint64_t generation = 2; generation <= maxKeyslotsPerArchive + 1; ++generation) {
        auto appendFile = File::openAppend(path);
        REQUIRE(appendFile);
        WriterSecrets secrets = testWriterSecrets();
        ReaderUnlock unlock = testUnlock();
        auto writer = Writer::appendEncrypted(
            std::move(*appendFile),
            options,
            std::move(secrets),
            std::move(unlock)
        );
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("v")));
        REQUIRE(writer->finish());
    }
    // NOTE: 65 keyslot records exceed the cap, so the open fails before unbounded KDF work.
    auto readFile = File::openRead(path);
    REQUIRE(readFile);
    ReaderUnlock unlock = testUnlock();
    auto reader = Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(unlock));
    REQUIRE_FALSE(reader);
    CHECK(reader.error().kind == ErrorKind::LimitExceeded);

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

TEST_CASE("truncated archive opens as the earlier generation") {
    // NOTE: rollback to a complete older generation is undetectable in any append-only archive
    // (plaintext behaves the same) and is a documented property, not a defect: generations are
    // self-validating, so the prefix opens cleanly as what it is.
    auto path = tempArchive("bale-enc-rollback.bale");
    auto gen1Path = tempArchive("bale-enc-rollback-gen1.bale");
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterSecrets first = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(first));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("first")));
        REQUIRE(writer->finish());
    }
    writeBytes(gen1Path, test::readAll(path));
    {
        auto appendFile = File::openAppend(path);
        REQUIRE(appendFile);
        WriterSecrets second = testWriterSecrets();
        ReaderUnlock appendUnlock = testUnlock();
        auto writer2 = Writer::appendEncrypted(
            std::move(*appendFile),
            options,
            std::move(second),
            std::move(appendUnlock)
        );
        REQUIRE(writer2);
        REQUIRE(writer2->addBytes("a.txt", bytesOf("second")));
        REQUIRE(writer2->finish());
    }

    auto readFile = File::openRead(gen1Path);
    REQUIRE(readFile);
    ReaderUnlock unlock = testUnlock();
    auto reader = Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(unlock));
    REQUIRE(reader);
    CHECK(reader->commit().generation == 1);
    CHECK(reader->ignoredTrailingBytes() == 0);
    auto report = reader->verify(VerifyMode::Content);
    CHECK(report.has_value());

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(gen1Path, ignored);
}

TEST_CASE("wrong password and corrupt archive stay distinguishable") {
    // NOTE: distinct errors are deliberate UX, pinned so nobody merges them: PasswordRequired
    // tells the user to retry the password, Integrity says the archive itself is damaged.
    auto path = tempArchive("bale-enc-oracle.bale");
    auto corruptPath = tempArchive("bale-enc-oracle-corrupt.bale");
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterSecrets secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("secret bytes here")));
        REQUIRE(writer->finish());
    }

    auto wrongFile = File::openRead(path);
    REQUIRE(wrongFile);
    ReaderUnlock wrong;
    wrong.hasPassword = true;
    auto made = crypto::SecretBytes::make(7);
    REQUIRE(made);
    wrong.password = std::move(*made);
    std::string_view bad = "bad-pw!";
    std::ranges::copy(std::as_bytes(std::span(bad)), wrong.password.mut().begin());
    auto wrongReader =
        Reader::openEncrypted(std::move(*wrongFile), ReaderOptions{}, std::move(wrong));
    REQUIRE_FALSE(wrongReader);
    CHECK(wrongReader.error().kind == ErrorKind::PasswordRequired);

    auto bytes = test::readAll(path);
    REQUIRE(bytes.size() > footerSize + recordFramingSize);
    auto footerBytes = std::span(bytes).subspan(bytes.size() - footerSize, footerSize);
    REQUIRE(std::ranges::equal(footerBytes.first<8>(), std::span(footerMagic).first<8>()));
    std::uint64_t commitOffset = loadLe<std::uint64_t>(footerBytes.data() + 8);
    bytes[static_cast<std::size_t>(commitOffset + recordPrefixSize)] = static_cast<std::byte>(
        bytes[static_cast<std::size_t>(commitOffset + recordPrefixSize)] ^ std::byte{0x01}
    );
    writeBytes(corruptPath, bytes);

    auto corruptFile = File::openRead(corruptPath);
    REQUIRE(corruptFile);
    ReaderUnlock right = testUnlock();
    auto corruptReader =
        Reader::openEncrypted(std::move(*corruptFile), ReaderOptions{}, std::move(right));
    REQUIRE_FALSE(corruptReader);
    CHECK(corruptReader.error().kind == ErrorKind::Integrity);
    CHECK(wrongReader.error().kind != corruptReader.error().kind);

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(corruptPath, ignored);
}

TEST_CASE("compacted archive keeps valid tags with fresh metadata nonces") {
    auto path = tempArchive("bale-enc-compact.bale");
    auto compactedPath = tempArchive("bale-enc-compact-out.bale");
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterSecrets secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("alpha content")));
        REQUIRE(writer->addBytes("b.txt", bytesOf("beta content")));
        REQUIRE(writer->finish());
    }
    {
        auto readFile = File::openRead(path);
        REQUIRE(readFile);
        ReaderUnlock unlock = testUnlock();
        auto reader =
            Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(unlock));
        REQUIRE(reader);
        auto outFile = File::createNew(compactedPath);
        REQUIRE(outFile);
        auto summary = Writer::compactEncrypted(std::move(*outFile), *reader, false);
        REQUIRE(summary);
    }

    auto original = test::readAll(path);
    auto compacted = test::readAll(compactedPath);
    auto originalRecords = scanAllRecords(original);
    auto compactedRecords = scanAllRecords(compacted);

    // NOTE: data payloads copy verbatim (offsets are not in the AAD, so tags stay valid at new
    // positions) while metadata is re-sealed under fresh nonces.
    std::vector<std::vector<std::byte>> originalData;
    std::vector<std::vector<std::byte>> compactedData;
    std::vector<std::byte> originalManifestNonce;
    std::vector<std::byte> compactedManifestNonce;
    for (const auto& record : originalRecords) {
        if (record.type == RecordType::Data) {
            originalData.push_back(record.payload);
        }
        if (record.type == RecordType::Manifest && originalManifestNonce.empty()) {
            originalManifestNonce.assign(record.payload.begin(), record.payload.begin() + 24);
        }
    }
    for (const auto& record : compactedRecords) {
        if (record.type == RecordType::Data) {
            compactedData.push_back(record.payload);
        }
        if (record.type == RecordType::Manifest && compactedManifestNonce.empty()) {
            compactedManifestNonce.assign(record.payload.begin(), record.payload.begin() + 24);
        }
    }
    REQUIRE(!originalData.empty());
    CHECK(compactedData == originalData);
    REQUIRE(compactedManifestNonce.size() == 24);
    CHECK(compactedManifestNonce != originalManifestNonce);

    auto readCompacted = File::openRead(compactedPath);
    REQUIRE(readCompacted);
    ReaderUnlock compactUnlock = testUnlock();
    auto compactedReader =
        Reader::openEncrypted(std::move(*readCompacted), ReaderOptions{}, std::move(compactUnlock));
    REQUIRE(compactedReader);
    CHECK(compactedReader->epoch() == 1);
    CHECK(compactedReader->manifest().entries.size() == 2);
    auto report = compactedReader->verify(VerifyMode::Content);
    REQUIRE(report);
    CHECK(report->chunksVerified == 2);

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(compactedPath, ignored);
}

TEST_CASE("record nonces and object ids never repeat under one key") {
    auto path = tempArchive("bale-enc-nonces.bale");
    WriterOptions options = fixedOptions(minChunkSize);
    options.experimentalEncryption = true;
    auto file = File::createNew(path);
    REQUIRE(file);
    WriterSecrets secrets = testWriterSecrets();
    auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
    REQUIRE(writer);
    for (int entry = 0; entry < 3; ++entry) {
        std::vector<std::byte> content(10000);
        for (std::size_t index = 0; index < content.size(); ++index) {
            content[index] =
                static_cast<std::byte>((index * 31 + static_cast<std::size_t>(entry) * 7) % 251);
        }
        std::string name = "file" + std::to_string(entry) + ".bin";
        REQUIRE(writer->addBytes(name, content));
    }
    REQUIRE(writer->finish());

    // NOTE: every data record carries a fresh 24-byte nonce and 32-byte object id from
    // libsodium's RNG; a repeat under one key would break nonce reuse guarantees.
    auto bytes = test::readAll(path);
    auto records = scanAllRecords(bytes);
    std::set<std::vector<std::byte>> nonces;
    std::set<std::vector<std::byte>> objects;
    std::size_t dataRecords = 0;
    for (const auto& record : records) {
        if (record.type != RecordType::Data) {
            continue;
        }
        ++dataRecords;
        REQUIRE(record.payload.size() >= encryptedDataHeaderSize);
        objects.insert(std::vector<std::byte>(record.payload.begin(), record.payload.begin() + 32));
        nonces.insert(
            std::vector<std::byte>(record.payload.begin() + 40, record.payload.begin() + 64)
        );
    }
    REQUIRE(dataRecords > 1);
    CHECK(objects.size() == dataRecords);
    CHECK(nonces.size() == dataRecords);

    std::set<std::array<std::byte, crypto::nonceSize>> freshNonces;
    std::set<ObjectId> freshObjects;
    for (int draw = 0; draw < 256; ++draw) {
        auto nonce = crypto::makeNonce();
        REQUIRE(nonce);
        CHECK(freshNonces.insert(*nonce).second);
        auto object = makeObjectId();
        REQUIRE(object);
        CHECK(freshObjects.insert(*object).second);
    }

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

TEST_CASE("data header bytes the reader trusts are authenticated") {
    // NOTE: object id, epoch and codec ride in the record header in the clear; each is covered
    // by the data AAD (and cross-checked against the index and commit). Offsets are the
    // deliberate exception: they are not in any AAD so compaction can relocate records.
    auto path = tempArchive("bale-enc-aad.bale");
    WriterOptions writeOptions = fixedOptions();
    writeOptions.experimentalEncryption = true;
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterSecrets secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), writeOptions, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("aad-bound content for header tests")));
        REQUIRE(writer->finish());
    }
    auto bytes = test::readAll(path);
    auto records = scanAllRecords(bytes);
    const auto* data = findFirstRecord(records, RecordType::Data);
    REQUIRE(data != nullptr);
    REQUIRE(data->payload.size() > encryptedDataHeaderSize);

    auto openWith = [&](const std::vector<std::byte>& mutated) {
        auto mutatedPath = tempArchive("bale-enc-aad-mut.bale");
        writeBytes(mutatedPath, mutated);
        auto mutatedFile = File::openRead(mutatedPath);
        REQUIRE(mutatedFile);
        ReaderUnlock unlock = testUnlock();
        return Reader::openEncrypted(std::move(*mutatedFile), ReaderOptions{}, std::move(unlock));
    };
    auto firstExtent = [](Reader& reader) {
        const auto& entry = reader.manifest().entries.front();
        auto objects =
            std::span(reader.manifest().objectIds).subspan(entry.firstChunk, entry.chunkCount);
        auto plains = reader.manifest().chunksOf(entry);
        return reader.loadEncryptedExtent(objects[0], plains[0]);
    };

    // NOTE: epoch tampering keeps framing valid (trailer repaired) but the record no longer
    // matches the commit epoch.
    {
        auto mutated = bytes;
        auto at = static_cast<std::size_t>(data->offset + recordPrefixSize + 32);
        mutated[at] = static_cast<std::byte>(mutated[at] ^ std::byte{0x01});
        repairPayloadCrc(mutated, *data);
        auto reader = openWith(mutated);
        REQUIRE(reader);
        auto extent = firstExtent(*reader);
        REQUIRE_FALSE(extent);
        CHECK(extent.error().kind == ErrorKind::Malformed);
    }
    // NOTE: object-id tampering keeps framing valid but the record no longer matches the index.
    {
        auto mutated = bytes;
        auto at = static_cast<std::size_t>(data->offset + recordPrefixSize);
        mutated[at] = static_cast<std::byte>(mutated[at] ^ std::byte{0x01});
        repairPayloadCrc(mutated, *data);
        auto reader = openWith(mutated);
        REQUIRE(reader);
        auto extent = firstExtent(*reader);
        REQUIRE_FALSE(extent);
        CHECK(extent.error().kind == ErrorKind::Malformed);
    }
    // NOTE: codec tampering keeps framing valid but the record no longer matches the index codec.
    {
        auto mutated = bytes;
        auto at = static_cast<std::size_t>(data->offset + 32);
        mutated[at] = std::byte{0xFF};
        repairPrefixCrc(mutated, data->offset);
        auto reader = openWith(mutated);
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Malformed);
    }

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(tempArchive("bale-enc-aad-mut.bale"), ignored);
}

TEST_CASE("downgrade and mixing attempts fail cleanly") {
    auto encPath = tempArchive("bale-enc-downgrade.bale");
    WriterOptions encOptions = fixedOptions();
    encOptions.experimentalEncryption = true;
    {
        auto file = File::createNew(encPath);
        REQUIRE(file);
        WriterSecrets secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), encOptions, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("downgrade matrix content")));
        REQUIRE(writer->finish());
    }
    auto plainPath = tempArchive("bale-plain-downgrade.bale");
    {
        auto file = File::createNew(plainPath);
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), fixedOptions());
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("downgrade matrix content")));
        REQUIRE(writer->finish());
    }

    auto encBytes = test::readAll(encPath);
    auto encRecords = scanAllRecords(encBytes);
    const auto* encData = findFirstRecord(encRecords, RecordType::Data);
    const auto* encCommit = findFirstRecord(encRecords, RecordType::Commit);
    REQUIRE(encData != nullptr);
    REQUIRE(encCommit != nullptr);

    auto plainBytes = test::readAll(plainPath);
    auto plainRecords = scanAllRecords(plainBytes);
    const auto* plainData = findFirstRecord(plainRecords, RecordType::Data);
    REQUIRE(plainData != nullptr);

    auto openEncryptedBytes = [&](const std::vector<std::byte>& mutated) {
        auto mutatedPath = tempArchive("bale-enc-mix.bale");
        writeBytes(mutatedPath, mutated);
        auto mutatedFile = File::openRead(mutatedPath);
        REQUIRE(mutatedFile);
        ReaderUnlock unlock = testUnlock();
        return Reader::openEncrypted(std::move(*mutatedFile), ReaderOptions{}, std::move(unlock));
    };

    // NOTE: a data record stripped of its encrypted flag is refused, not decrypted as plain.
    {
        auto mutated = encBytes;
        auto at = static_cast<std::size_t>(encData->offset + 6);
        mutated[at] = static_cast<std::byte>(static_cast<unsigned>(mutated[at]) & ~unsigned{0x01});
        repairPrefixCrc(mutated, encData->offset);
        auto reader = openEncryptedBytes(mutated);
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Malformed);
    }
    // NOTE: a commit stripped of its encrypted flag is refused before any key use.
    {
        auto mutated = encBytes;
        auto at = static_cast<std::size_t>(encCommit->offset + 6);
        mutated[at] = static_cast<std::byte>(static_cast<unsigned>(mutated[at]) & ~unsigned{0x01});
        repairPrefixCrc(mutated, encCommit->offset);
        auto reader = openEncryptedBytes(mutated);
        REQUIRE_FALSE(reader);
        CHECK(reader.error().kind == ErrorKind::Malformed);
    }
    // NOTE: an encrypted flag planted on a plaintext record is refused, not decrypted.
    // Plaintext open only finds the commit; the flag gate fires when records are walked.
    {
        auto mutated = plainBytes;
        auto at = static_cast<std::size_t>(plainData->offset + 6);
        mutated[at] = static_cast<std::byte>(static_cast<unsigned>(mutated[at]) | unsigned{0x01});
        repairPrefixCrc(mutated, plainData->offset);
        auto mutatedPath = tempArchive("bale-plain-mix.bale");
        writeBytes(mutatedPath, mutated);
        auto mutatedFile = File::openRead(mutatedPath);
        REQUIRE(mutatedFile);
        auto reader = Reader::open(std::move(*mutatedFile));
        REQUIRE(reader);
        auto report = reader->verify(VerifyMode::Structure);
        REQUIRE_FALSE(report);
        CHECK(report.error().kind == ErrorKind::Unsupported);
        std::error_code ignoredMix;
        std::filesystem::remove(mutatedPath, ignoredMix);
    }
    // NOTE: without the password nothing leaks: the plaintext path stops at the feature flag
    // before touching any entry, and the encrypted path demands a keyslot unlock first.
    {
        auto encFile = File::openRead(encPath);
        REQUIRE(encFile);
        auto plainReader = Reader::open(std::move(*encFile));
        REQUIRE_FALSE(plainReader);
        CHECK(plainReader.error().kind == ErrorKind::PasswordRequired);
    }
    {
        auto encFile = File::openRead(encPath);
        REQUIRE(encFile);
        ReaderUnlock empty;
        auto locked = Reader::openEncrypted(std::move(*encFile), ReaderOptions{}, std::move(empty));
        REQUIRE_FALSE(locked);
        CHECK(locked.error().kind == ErrorKind::PasswordRequired);
    }

    std::error_code ignored;
    std::filesystem::remove(encPath, ignored);
    std::filesystem::remove(plainPath, ignored);
    std::filesystem::remove(tempArchive("bale-enc-mix.bale"), ignored);
}
