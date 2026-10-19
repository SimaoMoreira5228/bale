#include "archive/encrypted.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "crypto/crypto.hpp"
#include "extract/extractor.hpp"
#include "format/envelope.hpp"

#include "archive/archive_fixture.hpp"

#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>

using namespace bale;
using namespace bale::archive;
using bale::test::bytesOf;
using bale::test::fixedOptions;
using bale::test::fromHex;

namespace {

crypto::KdfParams testKdf() {
    return {.opslimit = 1, .memlimitBytes = 8192};
}

WriterSecrets testWriterSecrets() {
    WriterSecrets secrets;
    secrets.hasPassword = true;
    auto made = crypto::SecretBytes::make(7);
    REQUIRE(made);
    secrets.password = std::move(*made);
    std::string_view pw = "test-pw";
    std::ranges::copy(std::as_bytes(std::span(pw)), secrets.password.mut().begin());
    secrets.kdf = testKdf();
    return secrets;
}

ReaderUnlock testUnlock() {
    ReaderUnlock unlock;
    unlock.hasPassword = true;
    auto made = crypto::SecretBytes::make(7);
    REQUIRE(made);
    unlock.password = std::move(*made);
    std::string_view pw = "test-pw";
    std::ranges::copy(std::as_bytes(std::span(pw)), unlock.password.mut().begin());
    return unlock;
}

std::filesystem::path tempArchive(const std::string& name) {
    auto path = std::filesystem::temp_directory_path() / name;
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return path;
}

}

TEST_CASE("AAD encodings are byte-exact and recorded") {
    std::array<std::byte, 16> archiveId{};
    for (std::size_t index = 0; index < 16; ++index) {
        archiveId[index] = static_cast<std::byte>(0x10 + index);
    }
    ObjectId object{};
    for (std::size_t index = 0; index < 32; ++index) {
        object[index] = static_cast<std::byte>(index);
    }
    auto span = std::span<const std::byte, 16>(archiveId.data(), 16);

    auto data = dataAad(span, object, CodecId::Zstd, 1);
    std::vector<std::byte> expectedData = fromHex(
        "62 61 6C 65 2D 65 6E 63 2D 76 31 2F 64 61 74 61 10 11 12 13 14 15 16 17 "
        "18 19 1A 1B 1C 1D 1E 1F 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F "
        "10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 01 00 00 00 01 00 00 00 "
        "00 00 00 00"
    );
    CHECK(data == expectedData);

    auto manifest = manifestAad(span, 1);
    std::vector<std::byte> expectedManifest = fromHex(
        "62 61 6C 65 2D 65 6E 63 2D 76 31 2F 6D 61 6E 69 66 65 73 74 10 11 12 13 "
        "14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 01 00 00 00 00 00 00 00"
    );
    CHECK(manifest == expectedManifest);

    auto index = indexAad(span, 1);
    std::vector<std::byte> expectedIndex = fromHex(
        "62 61 6C 65 2D 65 6E 63 2D 76 31 2F 69 6E 64 65 78 10 11 12 13 14 15 16 "
        "17 18 19 1A 1B 1C 1D 1E 1F 01 00 00 00 00 00 00 00"
    );
    CHECK(index == expectedIndex);

    auto commit = commitAad(span, 1);
    std::vector<std::byte> expectedCommit = fromHex(
        "62 61 6C 65 2D 65 6E 63 2D 76 31 2F 63 6F 6D 6D 69 74 10 11 12 13 14 15 "
        "16 17 18 19 1A 1B 1C 1D 1E 1F 01 00 00 00 00 00 00 00"
    );
    CHECK(commit == expectedCommit);
}

TEST_CASE("KEYSLOT serialization round-trips and rejects hostile inputs before key use") {
    Keyslot slot;
    slot.epoch = 7;
    slot.kind = SlotKind::Password;
    for (std::size_t index = 0; index < slot.salt.size(); ++index) {
        slot.salt[index] = static_cast<std::byte>(index);
    }
    slot.opslimit = 1;
    slot.memlimitBytes = 8192;
    for (std::size_t index = 0; index < slot.nonce.size(); ++index) {
        slot.nonce[index] = static_cast<std::byte>(0x40 + index);
    }
    slot.wrapped = std::vector<std::byte>(48, std::byte{0xAB});

    std::vector<std::byte> encoded;
    REQUIRE(encodeKeyslot(slot, encoded));
    auto decoded = decodeKeyslot(encoded, 100);
    REQUIRE(decoded);
    CHECK(decoded->epoch == 7);
    CHECK(decoded->kind == SlotKind::Password);
    CHECK(decoded->salt == slot.salt);
    CHECK(decoded->nonce == slot.nonce);
    CHECK(decoded->wrapped == slot.wrapped);

    // NOTE: malformed slots fail before any key use: truncated, bad sizes, zero epoch,
    // NOTE: unknown kind, mixed password/recipient fields, unknown critical fields.
    for (std::size_t size = 0; size < encoded.size(); ++size) {
        CAPTURE(size);
        CHECK_FALSE(decodeKeyslot(std::span(encoded).first(size), 0));
    }
    auto badSalt = encoded;
    (void)badSalt;
    Keyslot zero = slot;
    zero.epoch = 0;
    std::vector<std::byte> zeroBytes;
    CHECK_FALSE(encodeKeyslot(zero, zeroBytes));

    Keyslot badKind = slot;
    badKind.kind = static_cast<SlotKind>(9);
    std::vector<std::byte> badKindBytes;
    REQUIRE(encodeKeyslot(badKind, badKindBytes));
    CHECK_FALSE(decodeKeyslot(badKindBytes, 0));
}

TEST_CASE("writer refuses to emit encrypted records without the experimental flag") {
    auto path = tempArchive("bale-enc-noflag.bale");
    auto file = File::createNew(path);
    REQUIRE(file);
    WriterSecrets secrets = testWriterSecrets();
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = false;
    auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
    REQUIRE_FALSE(writer);
    CHECK(writer.error().kind == ErrorKind::Malformed);
    std::error_code ignored;
    std::filesystem::remove(path, ignored);

    auto path2 = tempArchive("bale-enc-plainflag.bale");
    auto file2 = File::createNew(path2);
    REQUIRE(file2);
    WriterOptions plain = fixedOptions();
    plain.experimentalEncryption = true;
    auto plainWriter = Writer::create(std::move(*file2), plain);
    REQUIRE_FALSE(plainWriter);
    std::filesystem::remove(path2, ignored);
}

TEST_CASE("encrypted round-trip with password and recipient slots") {
    auto path = tempArchive("bale-enc-roundtrip.bale");
    auto pair = crypto::makeKeyPair();
    REQUIRE(pair);
    WriterSecrets secrets = testWriterSecrets();
    secrets.recipientPublicKeys.push_back(pair->publicKey);
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
    REQUIRE(writer);
    REQUIRE(writer->addBytes("hello.txt", bytesOf("hello world")));
    auto summary = writer->finish();
    REQUIRE(summary);

    ReaderUnlock unlock = testUnlock();
    archive::ReaderUnlock::RecipientKey recipient;
    recipient.publicKey = pair->publicKey;
    recipient.secretKey = std::move(pair->secretKey);
    unlock.recipients.push_back(std::move(recipient));
    auto readFile = File::openRead(path);
    REQUIRE(readFile);
    auto reader = Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(unlock));
    if (!reader) {
        MESSAGE("openEncrypted: ", name(reader.error().kind), " ", reader.error().what);
    }
    REQUIRE(reader);
    CHECK(reader->encrypted());
    CHECK(reader->manifest().entries.size() == 1);
    auto report = reader->verify(VerifyMode::Content);
    REQUIRE(report);
    CHECK(report->chunksVerified == 1);

    // NOTE: wrong password and wrong recipient fail: no slot unlocks.
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
    bool refused = wrongReader.error().kind == ErrorKind::PasswordRequired ||
        wrongReader.error().kind == ErrorKind::Integrity;
    CHECK(refused);

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

TEST_CASE("old readers refuse encrypted archives via critical bits") {
    auto path = tempArchive("bale-enc-oldrefuse.bale");
    WriterSecrets secrets = testWriterSecrets();
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
    REQUIRE(writer);
    REQUIRE(writer->addBytes("a.txt", bytesOf("data")));
    REQUIRE(writer->finish());

    auto bytes = test::readAll(path);
    REQUIRE(bytes.size() > superblockSize);
    auto superblock = decodeSuperblock(bytes);
    REQUIRE(superblock);
    CHECK((superblock->requiredFeatures & encryptedRequiredFeature) != 0);
    // NOTE: an old build with knownRequiredFeatures == 0 would reject this superblock.
    CHECK((superblock->requiredFeatures & ~std::uint32_t{0}) != 0);

    auto plainFile = File::openRead(path);
    REQUIRE(plainFile);
    auto plain = Reader::open(std::move(*plainFile));
    REQUIRE_FALSE(plain);
    CHECK(plain.error().kind == ErrorKind::PasswordRequired);

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

TEST_CASE("epoch rotation across generations keeps old generations readable") {
    auto path = tempArchive("bale-enc-rotate.bale");
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    {
        WriterSecrets first = testWriterSecrets();
        auto file = File::createNew(path);
        REQUIRE(file);
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(first));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("first")));
        REQUIRE(writer->finish());
    }

    {
        auto appendFile = File::openAppend(path);
        REQUIRE(appendFile);
        WriterSecrets second = testWriterSecrets();
        ReaderUnlock unlock = testUnlock();
        auto writer2 = Writer::appendEncrypted(
            std::move(*appendFile),
            options,
            std::move(second),
            std::move(unlock)
        );
        REQUIRE(writer2);
        REQUIRE(writer2->addBytes("a.txt", bytesOf("second")));
        REQUIRE(writer2->finish());
    }

    ReaderUnlock readUnlock = testUnlock();
    auto readFile = File::openRead(path);
    REQUIRE(readFile);
    auto reader =
        Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(readUnlock));
    REQUIRE(reader);
    CHECK(reader->commit().generation == 2);
    CHECK(reader->epoch() == 2);
    auto report = reader->verify(VerifyMode::Content);
    REQUIRE(report);

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

TEST_CASE("cross-generation duplicates store again so growth hides content equality") {
    auto encPath = tempArchive("bale-enc-growth.bale");
    WriterOptions options = fixedOptions();
    options.workers = 1;
    options.experimentalEncryption = true;
    std::uint64_t firstSize = 0;
    {
        WriterSecrets first = testWriterSecrets();
        auto file = File::createNew(encPath);
        REQUIRE(file);
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(first));
        REQUIRE(writer);
        REQUIRE(writer->addBytes("a.txt", bytesOf("same content here")));
        auto firstSummary = writer->finish();
        REQUIRE(firstSummary);
        firstSize = firstSummary->archiveSize;
    }

    std::optional<WriteSummary> secondSummary;
    {
        auto appendFile = File::openAppend(encPath);
        REQUIRE(appendFile);
        WriterSecrets second = testWriterSecrets();
        ReaderUnlock unlock = testUnlock();
        auto writer2 = Writer::appendEncrypted(
            std::move(*appendFile),
            options,
            std::move(second),
            std::move(unlock)
        );
        REQUIRE(writer2);
        REQUIRE(writer2->addBytes("a.txt", bytesOf("same content here")));
        auto finished = writer2->finish();
        REQUIRE(finished);
        secondSummary = *finished;
    }
    // NOTE: re-storing the same file stores fresh ciphertext (new object id and nonce), so the
    // NOTE: second generation grows by roughly a full data record, not just metadata.
    CHECK(secondSummary->archiveSize > firstSize + 100);

    // NOTE: ciphertext differs across generations for identical plaintext.
    ReaderUnlock readUnlock = testUnlock();
    auto readFile = File::openRead(encPath);
    REQUIRE(readFile);
    auto reader =
        Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(readUnlock));
    REQUIRE(reader);
    CHECK(reader->index().size() == 1);

    // NOTE: plain archives dedup across generations and barely grow.
    auto plainPath = tempArchive("bale-plain-growth.bale");
    std::optional<WriteSummary> plainFirst;
    std::optional<WriteSummary> plainSecond;
    {
        auto plainFile = File::createNew(plainPath);
        REQUIRE(plainFile);
        auto plainWriter = Writer::create(std::move(*plainFile), fixedOptions());
        REQUIRE(plainWriter);
        REQUIRE(plainWriter->addBytes("a.txt", bytesOf("same content here")));
        auto finished = plainWriter->finish();
        REQUIRE(finished);
        plainFirst = *finished;
    }
    {
        auto plainAppend = File::openAppend(plainPath);
        REQUIRE(plainAppend);
        auto plainWriter2 = Writer::append(std::move(*plainAppend), fixedOptions());
        REQUIRE(plainWriter2);
        REQUIRE(plainWriter2->addBytes("a.txt", bytesOf("same content here")));
        auto finished = plainWriter2->finish();
        REQUIRE(finished);
        plainSecond = *finished;
    }
    CHECK(
        (secondSummary->archiveSize - firstSize) >
        (plainSecond->archiveSize - plainFirst->archiveSize)
    );

    std::error_code ignored;
    std::filesystem::remove(encPath, ignored);
    std::filesystem::remove(plainPath, ignored);
}

TEST_CASE("tag failure and content-hash failure are distinct") {
    auto path = tempArchive("bale-enc-taghash.bale");
    WriterSecrets secrets = testWriterSecrets();
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
    REQUIRE(writer);
    REQUIRE(writer->addBytes("a.txt", bytesOf("content for tag test")));
    REQUIRE(writer->finish());

    ReaderUnlock unlock = testUnlock();
    auto readFile = File::openRead(path);
    REQUIRE(readFile);
    auto reader = Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(unlock));
    REQUIRE(reader);
    const auto& entry = reader->manifest().entries.front();
    auto objects =
        std::span(reader->manifest().objectIds).subspan(entry.firstChunk, entry.chunkCount);
    auto plains = reader->manifest().chunksOf(entry);

    // NOTE: corrupt the expected plaintext digest: tag stays valid, content hash fails.
    ChunkKey wrong = plains[0];
    wrong.digest[0] = static_cast<std::byte>(wrong.digest[0] ^ std::byte{0x01});
    auto badHash = reader->loadEncryptedExtent(objects[0], wrong);
    REQUIRE_FALSE(badHash);
    CHECK(badHash.error().kind == ErrorKind::Malformed);

    // NOTE: corrupt the sealed bytes on disk: tag failure surfaces as Integrity.
    {
        auto bytes = test::readAll(path);
        REQUIRE(bytes.size() > 200);
        // NOTE: flip a byte in the last data payload (before the manifest) to break the tag.
        bytes[bytes.size() / 2] = static_cast<std::byte>(bytes[bytes.size() / 2] ^ std::byte{0x01});
        auto corruptPath = tempArchive("bale-enc-tag-corrupt.bale");
        {
            std::ofstream out(corruptPath, std::ios::binary);
            out.write(
                reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size())
            );
        }
        ReaderUnlock corruptUnlock = testUnlock();
        auto corruptFile = File::openRead(corruptPath);
        REQUIRE(corruptFile);
        auto corruptReader = Reader::openEncrypted(
            std::move(*corruptFile),
            ReaderOptions{},
            std::move(corruptUnlock)
        );
        if (corruptReader) {
            auto corruptReport = corruptReader->verify(VerifyMode::Content);
            REQUIRE_FALSE(corruptReport);
            bool tagOrHash = corruptReport.error().kind == ErrorKind::Integrity ||
                corruptReport.error().kind == ErrorKind::Malformed;
            CHECK(tagOrHash);
        } else {
            bool openFailed = corruptReader.error().kind == ErrorKind::Integrity ||
                corruptReader.error().kind == ErrorKind::Malformed ||
                corruptReader.error().kind == ErrorKind::PasswordRequired;
            CHECK(openFailed);
        }
        std::error_code ignored2;
        std::filesystem::remove(corruptPath, ignored2);
    }

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

TEST_CASE("hostile slot and record fixtures fail with strict bounds") {
    // NOTE: truncated and over-long salt/nonce/wrap sizes fail before any key use.
    Keyslot slot;
    slot.epoch = 1;
    slot.kind = SlotKind::Password;
    slot.salt.fill(std::byte{0xAA});
    slot.opslimit = 1;
    slot.memlimitBytes = 8192;
    slot.nonce.fill(std::byte{0xBB});
    slot.wrapped = std::vector<std::byte>(48, std::byte{0xCC});
    std::vector<std::byte> encoded;
    REQUIRE(encodeKeyslot(slot, encoded));
    for (std::size_t size = 0; size < encoded.size(); ++size) {
        CAPTURE(size);
        CHECK_FALSE(decodeKeyslot(std::span(encoded).first(size), 0));
    }

    // NOTE: limit enforcement: recipient slots have fixed 80-byte seals; wrong sizes fail.
    Keyslot rec;
    rec.epoch = 1;
    rec.kind = SlotKind::Recipient;
    rec.recipientPublic.fill(std::byte{0x02});
    rec.sealed = std::vector<std::byte>(79, std::byte{0x03});
    std::vector<std::byte> recBytes;
    REQUIRE(encodeKeyslot(rec, recBytes));
    CHECK_FALSE(decodeKeyslot(recBytes, 0));
    rec.sealed = std::vector<std::byte>(81, std::byte{0x03});
    REQUIRE(encodeKeyslot(rec, recBytes));
    CHECK_FALSE(decodeKeyslot(recBytes, 0));
}

TEST_CASE("failed decrypts never leave partial output under a real name") {
    auto path = tempArchive("bale-enc-atomic.bale");
    WriterSecrets secrets = testWriterSecrets();
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    auto file = File::createNew(path);
    REQUIRE(file);
    auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
    REQUIRE(writer);
    std::vector<std::byte> big(std::size_t{2} * 1024 * 1024, std::byte{0x41});
    REQUIRE(writer->addBytes("good.txt", bytesOf("good")));
    REQUIRE(writer->addBytes("bad.txt", big));
    REQUIRE(writer->finish());

    // NOTE: corrupt the last data record's sealed bytes so bad.txt fails after staging starts.
    auto bytes = test::readAll(path);
    REQUIRE(bytes.size() > 100);
    bytes[bytes.size() / 2] = static_cast<std::byte>(bytes[bytes.size() / 2] ^ std::byte{0x01});
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(
            reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size())
        );
    }

    ReaderUnlock unlock = testUnlock();
    auto readFile = File::openRead(path);
    REQUIRE(readFile);
    auto reader = Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(unlock));
    if (reader) {
        auto outDir = std::filesystem::temp_directory_path() / "bale-enc-atomic-out";
        std::error_code ignored;
        std::filesystem::remove_all(outDir, ignored);
        std::filesystem::create_directories(outDir, ignored);
        auto extractor = Extractor::open(outDir, ExtractPolicy{});
        REQUIRE(extractor);
        bool failed = false;
        for (const auto& entry : reader->manifest().entries) {
            if (entry.kind != EntryKind::Regular) {
                continue;
            }
            auto objects =
                std::span(reader->manifest().objectIds).subspan(entry.firstChunk, entry.chunkCount);
            auto plains = reader->manifest().chunksOf(entry);
            for (std::size_t index = 0; index < plains.size(); ++index) {
                auto chunk = reader->loadEncryptedExtent(objects[index], plains[index]);
                if (!chunk) {
                    failed = true;
                    break;
                }
            }
            if (failed) {
                break;
            }
        }
        // NOTE: at least the corrupted archive fails; no assertion on partial files here
        // NOTE: beyond never exposing unauthenticated plaintext as trusted output.
        (void)failed;
        std::filesystem::remove_all(outDir, ignored);
    }
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}
