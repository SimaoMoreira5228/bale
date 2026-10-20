#include "archive/reader.hpp"
#include "archive/signatures.hpp"
#include "archive/writer.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "cli/unlock.hpp"
#include "crypto/crypto_vectors.hpp"

#include "archive/archive_fixture.hpp"
#include "archive/encrypted_fixture.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace bale;
using namespace bale::archive;
using namespace bale::cli;
using bale::test::bytesOf;
using bale::test::fixedOptions;
using bale::test::readAll;
using bale::test::tempArchive;
using bale::test::TempPath;
using bale::test::testUnlock;
using bale::test::testWriterSecrets;

namespace {

constexpr std::string_view seedHex =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr std::string_view otherSeedHex =
    "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00";
constexpr std::string_view signerHex =
    "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
constexpr std::string_view signatureHex =
    "d27ebb1d73d9c96474fc1652ca1ce022d554dc0c5ae65f68abd2327553501696f"
    "b468f508310d5c4b2e4fe0e6ff47cd296d142e525a774dd6627837eac74d00b";
constexpr std::string_view signatureGen3Hex =
    "30e2c666a9edee2f73a8fa9460d932bfbd59ff08205eebff4a34ca0e19ad02e370"
    "af19b5d7dd89a6b48839ab36233d6450fb7d7978e7e3f14479e48b4df6600c";

crypto::SecretBytes seedFromHex(std::string_view hex) {
    auto raw = test::hexDecode(hex);
    auto made = crypto::SecretBytes::make(raw.size());
    REQUIRE(made);
    crypto::SecretBytes seed(std::move(*made));
    std::ranges::copy(raw, seed.mut().begin());
    return seed;
}

std::array<std::byte, 32> pubFromHex(std::string_view hex) {
    auto raw = test::hexDecode(hex);
    REQUIRE(raw.size() == 32);
    std::array<std::byte, 32> out{};
    std::ranges::copy(raw, out.begin());
    return out;
}

std::array<std::byte, 16> testArchiveId() {
    std::array<std::byte, 16> id{};
    for (std::size_t index = 0; index < id.size(); ++index) {
        id[index] = static_cast<std::byte>(0x10 + index);
    }
    return id;
}

std::array<std::byte, 32> testDigest() {
    std::array<std::byte, 32> digest{};
    for (std::size_t index = 0; index < digest.size(); ++index) {
        digest[index] = static_cast<std::byte>(0x20 + index);
    }
    return digest;
}

Writer signedWriter(const std::filesystem::path& path) {
    auto file = File::createNew(path);
    REQUIRE(file);
    auto options = fixedOptions();
    auto writer = Writer::create(std::move(*file), options);
    REQUIRE(writer);
    return std::move(*writer);
}

void writeTextFile(const std::filesystem::path& path, std::string_view text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    REQUIRE(out);
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    REQUIRE(out);
}

std::size_t findOffset(const std::vector<std::byte>& haystack, std::span<const std::byte> needle) {
    auto at = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
    if (at == haystack.end()) {
        return haystack.size();
    }
    return static_cast<std::size_t>(at - haystack.begin());
}

}

TEST_CASE("signature message domain separation is byte-exact and recorded") {
    auto id = testArchiveId();
    auto digest = testDigest();
    std::span<const std::byte, 16> idSpan(id.data(), 16);
    std::span<const std::byte, 32> digestSpan(digest.data(), 32);

    // NOTE: message layout is bale-sig-v1/commit || archive id || generation LE64
    // NOTE: || epoch LE64 || commit digest. This vector pins it byte for byte.
    auto message = signatureMessage(idSpan, 1, 0, digestSpan);
    CHECK(
        test::hexEncode(message) ==
        "62616c652d7369672d76312f636f6d6d6974101112131415161718191a1b1c1d1e1f"
        "01000000000000000000000000000000202122232425262728292a2b2c2d2e2f3031"
        "32333435363738393a3b3c3d3e3f"
    );

    auto seed = seedFromHex(seedHex);
    auto made = makeSignature(seed.bytes(), idSpan, 1, 0, digestSpan);
    REQUIRE(made);
    CHECK(test::hexEncode(made->signer) == std::string(signerHex));
    CHECK(test::hexEncode(made->signature) == std::string(signatureHex));
    CHECK(made->epoch == 0);

    auto madeGen3 = makeSignature(seed.bytes(), idSpan, 3, 3, digestSpan);
    REQUIRE(madeGen3);
    CHECK(madeGen3->signer == made->signer);
    CHECK(test::hexEncode(madeGen3->signature) == std::string(signatureGen3Hex));

    // NOTE: generation and epoch are inside the signed bytes: the gen3 answer must not
    // NOTE: verify as gen1, and a zero-epoch answer must not verify as epoch 3.
    auto key = pubFromHex(signerHex);
    CHECK(
        checkSignature(*made, key, idSpan, 3, 0, digestSpan).error().kind == ErrorKind::Integrity
    );
    CHECK(
        checkSignature(*made, key, idSpan, 1, 3, digestSpan).error().kind == ErrorKind::Integrity
    );
    CHECK(
        checkSignature(*madeGen3, key, idSpan, 1, 0, digestSpan).error().kind ==
        ErrorKind::Integrity
    );
    REQUIRE(checkSignature(*made, key, idSpan, 1, 0, digestSpan));
    REQUIRE(checkSignature(*madeGen3, key, idSpan, 3, 3, digestSpan));
}

TEST_CASE("SIGNATURE records round-trip and reject hostile inputs before use") {
    Signature signature;
    signature.epoch = 7;
    signature.signer = pubFromHex(signerHex);
    auto rawSig = test::hexDecode(signatureHex);
    std::ranges::copy(rawSig, signature.signature.begin());

    std::vector<std::byte> encoded;
    REQUIRE(encodeSignature(signature, encoded));
    auto decoded = decodeSignature(encoded, 100);
    REQUIRE(decoded);
    CHECK(decoded->epoch == 7);
    CHECK(decoded->signer == signature.signer);
    CHECK(decoded->signature == signature.signature);

    // NOTE: every truncation fails; nothing partial ever decodes.
    for (std::size_t size = 0; size < encoded.size(); ++size) {
        CAPTURE(size);
        CHECK_FALSE(decodeSignature(std::span(encoded).first(size), 0));
    }

    // NOTE: wrong-sized signer and signature fields fail instead of truncating.
    std::vector<std::byte> shortSigner(encoded.begin(), encoded.end() - 1);
    CHECK_FALSE(decodeSignature(shortSigner, 0));
    std::vector<std::byte> longSig = encoded;
    longSig.push_back(std::byte{0});
    CHECK_FALSE(decodeSignature(longSig, 0));

    // NOTE: a duplicated epoch field breaks the strictly increasing order, so it fails.
    std::vector<std::byte> duplicated = encoded;
    auto epochField = std::span(encoded).subspan(4, 3);
    duplicated.insert(duplicated.end(), epochField.begin(), epochField.end());
    CHECK_FALSE(decodeSignature(duplicated, 0));

    // NOTE: an unknown critical field after the signature fails instead of being ignored.
    std::vector<std::byte> unknownCritical = encoded;
    unknownCritical.push_back(std::byte{0x0D});
    unknownCritical.push_back(std::byte{0x01});
    unknownCritical.push_back(std::byte{0x00});
    CHECK_FALSE(decodeSignature(unknownCritical, 0));

    // NOTE: generation zero can never be signed.
    auto seed = seedFromHex(seedHex);
    auto id = testArchiveId();
    auto digest = testDigest();
    CHECK_FALSE(makeSignature(
        seed.bytes(),
        std::span<const std::byte, 16>(id.data(), 16),
        0,
        0,
        std::span<const std::byte, 32>(digest.data(), 32)
    ));
}

TEST_CASE("signed archives verify against the explicit key only") {
    TempPath temp;
    auto path = temp.path() / "signed.bale";
    std::filesystem::create_directories(temp.path());
    {
        auto writer = signedWriter(path);
        REQUIRE(writer.addSignSeed(seedFromHex(seedHex)));
        REQUIRE(writer.addBytes("a.txt", bytesOf("signed content")));
        REQUIRE(writer.finish());
    }

    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    REQUIRE(reader->hasSignatures());
    CHECK(reader->signatures().size() == 1);

    std::vector<std::array<std::byte, 32>> good{pubFromHex(signerHex)};
    REQUIRE(reader->verifySignatures(good));

    std::vector<std::array<std::byte, 32>> other{
        pubFromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")
    };
    auto wrong = reader->verifySignatures(other);
    REQUIRE_FALSE(wrong);
    CHECK(wrong.error().kind == ErrorKind::Integrity);

    std::vector<std::array<std::byte, 32>> empty;
    auto noKey = reader->verifySignatures(empty);
    REQUIRE_FALSE(noKey);
    CHECK(noKey.error().kind == ErrorKind::Malformed);

    // NOTE: structural verification is untouched by the presence of signatures.
    REQUIRE(reader->verify(VerifyMode::Content));

    TempPath plainTemp;
    auto plainPath = plainTemp.path() / "plain.bale";
    std::filesystem::create_directories(plainTemp.path());
    {
        auto writer = signedWriter(plainPath);
        REQUIRE(writer.addBytes("a.txt", bytesOf("unsigned content")));
        REQUIRE(writer.finish());
    }
    auto plainFile = File::openRead(plainPath);
    REQUIRE(plainFile);
    auto plain = Reader::open(std::move(*plainFile));
    REQUIRE(plain);
    CHECK_FALSE(plain->hasSignatures());
    REQUIRE(plain->verify(VerifyMode::Content));
    auto missing = plain->verifySignatures(good);
    REQUIRE_FALSE(missing);
    CHECK(missing.error().kind == ErrorKind::Integrity);
}

TEST_CASE("a signature covers exactly one commit generation") {
    TempPath temp;
    auto path = temp.path() / "rotated.bale";
    std::filesystem::create_directories(temp.path());
    {
        auto writer = signedWriter(path);
        REQUIRE(writer.addSignSeed(seedFromHex(seedHex)));
        REQUIRE(writer.addBytes("a.txt", bytesOf("first")));
        REQUIRE(writer.finish());
    }
    {
        auto appendFile = File::openAppend(path);
        REQUIRE(appendFile);
        auto writer = Writer::append(std::move(*appendFile), fixedOptions());
        REQUIRE(writer);
        REQUIRE(writer->addSignSeed(seedFromHex(otherSeedHex)));
        REQUIRE(writer->addBytes("a.txt", bytesOf("second")));
        REQUIRE(writer->finish());
    }

    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    REQUIRE(reader->commit().generation == 2);
    REQUIRE(reader->hasSignatures());
    CHECK(reader->signatures().size() == 1);

    // NOTE: the first-generation key no longer verifies: rotation means re-signing, and the
    // NOTE: old signature is history, not authority over the new commit.
    std::vector<std::array<std::byte, 32>> oldKey{pubFromHex(signerHex)};
    auto stale = reader->verifySignatures(oldKey);
    REQUIRE_FALSE(stale);
    CHECK(stale.error().kind == ErrorKind::Integrity);

    auto otherSeed = seedFromHex(otherSeedHex);
    auto otherPub = crypto::signPublicKeyOf(otherSeed.bytes());
    REQUIRE(otherPub);
    std::vector<std::array<std::byte, 32>> newKey{*otherPub};
    REQUIRE(reader->verifySignatures(newKey));
}

TEST_CASE("several signatures can share one commit") {
    TempPath temp;
    auto path = temp.path() / "multi.bale";
    std::filesystem::create_directories(temp.path());
    {
        auto writer = signedWriter(path);
        REQUIRE(writer.addSignSeed(seedFromHex(seedHex)));
        REQUIRE(writer.addSignSeed(seedFromHex(otherSeedHex)));
        REQUIRE(writer.addBytes("a.txt", bytesOf("two signers")));
        REQUIRE(writer.finish());
    }
    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    REQUIRE(reader->hasSignatures());
    CHECK(reader->signatures().size() == 2);

    // NOTE: any one of the commit's signers verifies; a third key does not.
    std::vector<std::array<std::byte, 32>> first{pubFromHex(signerHex)};
    REQUIRE(reader->verifySignatures(first));
    auto otherSeed = seedFromHex(otherSeedHex);
    auto otherPub = crypto::signPublicKeyOf(otherSeed.bytes());
    REQUIRE(otherPub);
    std::vector<std::array<std::byte, 32>> second{*otherPub};
    REQUIRE(reader->verifySignatures(second));
    std::vector<std::array<std::byte, 32>> both{first.front(), second.front()};
    REQUIRE(reader->verifySignatures(both));
    auto thirdPair = crypto::makeSignKeyPair();
    REQUIRE(thirdPair);
    std::vector<std::array<std::byte, 32>> third{thirdPair->publicKey};
    auto missing = reader->verifySignatures(third);
    REQUIRE_FALSE(missing);
    CHECK(missing.error().kind == ErrorKind::Integrity);
}

TEST_CASE("forged signatures fail verification") {
    auto seed = seedFromHex(seedHex);
    auto other = seedFromHex(otherSeedHex);
    auto id = testArchiveId();
    auto digest = testDigest();
    std::span<const std::byte, 16> idSpan(id.data(), 16);
    std::span<const std::byte, 32> digestSpan(digest.data(), 32);

    auto made = makeSignature(seed.bytes(), idSpan, 5, 0, digestSpan);
    REQUIRE(made);

    // NOTE: flipped signature bytes fail.
    Signature forged = *made;
    forged.signature[0] = static_cast<std::byte>(forged.signature[0] ^ std::byte{0x01});
    auto key = pubFromHex(signerHex);
    auto bad = checkSignature(forged, key, idSpan, 5, 0, digestSpan);
    REQUIRE_FALSE(bad);
    CHECK(bad.error().kind == ErrorKind::Integrity);

    // NOTE: a signature from another key fails even when presented with the right key.
    auto wrong = makeSignature(other.bytes(), idSpan, 5, 0, digestSpan);
    REQUIRE(wrong);
    auto swapped = checkSignature(*wrong, key, idSpan, 5, 0, digestSpan);
    REQUIRE_FALSE(swapped);
    CHECK(swapped.error().kind == ErrorKind::Integrity);

    // NOTE: a signature over the wrong digest fails.
    auto digest2 = digest;
    digest2[0] = static_cast<std::byte>(digest2[0] ^ std::byte{0x01});
    auto moved = checkSignature(
        *made,
        key,
        idSpan,
        5,
        0,
        std::span<const std::byte, 32>(digest2.data(), 32)
    );
    REQUIRE_FALSE(moved);
    CHECK(moved.error().kind == ErrorKind::Integrity);
}

TEST_CASE("writer refuses bad signing keys before emitting output") {
    TempPath temp;
    auto path = temp.path() / "badkey.bale";
    std::filesystem::create_directories(temp.path());
    auto writer = signedWriter(path);

    auto short_ = crypto::SecretBytes::make(16);
    REQUIRE(short_);
    auto refused = writer.addSignSeed(std::move(*short_));
    REQUIRE_FALSE(refused);
    CHECK(refused.error().kind == ErrorKind::Malformed);

    for (std::size_t count = 0; count < maxSignaturesPerCommit; ++count) {
        auto seed = seedFromHex(seedHex);
        REQUIRE(writer.addSignSeed(std::move(seed)));
    }
    auto overflow = writer.addSignSeed(seedFromHex(seedHex));
    REQUIRE_FALSE(overflow);
    CHECK(overflow.error().kind == ErrorKind::LimitExceeded);
}

TEST_CASE("compact refuses signed archives unless re-signed") {
    TempPath temp;
    std::filesystem::create_directories(temp.path());
    auto path = temp.path() / "src.bale";
    auto flat = temp.path() / "flat.bale";
    auto resigned = temp.path() / "resigned.bale";
    {
        auto writer = signedWriter(path);
        REQUIRE(writer.addSignSeed(seedFromHex(seedHex)));
        REQUIRE(writer.addBytes("a.txt", bytesOf("compact me")));
        REQUIRE(writer.finish());
    }

    auto openSource = [&]() {
        auto file = File::openRead(path);
        REQUIRE(file);
        auto reader = Reader::open(std::move(*file));
        REQUIRE(reader);
        return reader;
    };

    {
        auto source = openSource();
        auto out = File::createNew(flat);
        REQUIRE(out);
        auto compacted = Writer::compact(std::move(*out), *source, false);
        REQUIRE_FALSE(compacted);
        CHECK(compacted.error().kind == ErrorKind::Malformed);
    }
    {
        auto source = openSource();
        auto out = File::createNew(resigned);
        REQUIRE(out);
        std::vector<crypto::SecretBytes> seeds;
        seeds.push_back(seedFromHex(seedHex));
        auto compacted = Writer::compact(std::move(*out), *source, false, std::move(seeds));
        REQUIRE(compacted);
    }
    {
        auto file = File::openRead(resigned);
        REQUIRE(file);
        auto reader = Reader::open(std::move(*file));
        REQUIRE(reader);
        std::vector<std::array<std::byte, 32>> good{pubFromHex(signerHex)};
        REQUIRE(reader->verifySignatures(good));
    }

    // NOTE: an unsigned source compacts fine, and --sign signs the fresh commit.
    TempPath unsignedTemp;
    auto unsignedPath = unsignedTemp.path() / "plain.bale";
    auto unsignedCompact = unsignedTemp.path() / "plain-compact.bale";
    std::filesystem::create_directories(unsignedTemp.path());
    {
        auto writer = signedWriter(unsignedPath);
        REQUIRE(writer.addBytes("a.txt", bytesOf("plain compact")));
        REQUIRE(writer.finish());
    }
    {
        auto file = File::openRead(unsignedPath);
        REQUIRE(file);
        auto source = Reader::open(std::move(*file));
        REQUIRE(source);
        auto out = File::createNew(unsignedCompact);
        REQUIRE(out);
        std::vector<crypto::SecretBytes> seeds;
        seeds.push_back(seedFromHex(seedHex));
        auto compacted = Writer::compact(std::move(*out), *source, false, std::move(seeds));
        REQUIRE(compacted);
    }
    {
        auto file = File::openRead(unsignedCompact);
        REQUIRE(file);
        auto reader = Reader::open(std::move(*file));
        REQUIRE(reader);
        std::vector<std::array<std::byte, 32>> good{pubFromHex(signerHex)};
        REQUIRE(reader->verifySignatures(good));
    }
}

TEST_CASE("corrupt signature bytes fail loudly and distinctly") {
    TempPath temp;
    std::filesystem::create_directories(temp.path());
    auto path = temp.path() / "honest.bale";
    auto donorPath = temp.path() / "donor.bale";
    auto forgedPath = temp.path() / "forged.bale";
    auto transplantPath = temp.path() / "transplant.bale";
    auto brokenPath = temp.path() / "broken.bale";
    {
        auto writer = signedWriter(path);
        REQUIRE(writer.addSignSeed(seedFromHex(seedHex)));
        REQUIRE(writer.addBytes("a.txt", bytesOf("pinned content")));
        REQUIRE(writer.finish());
    }
    {
        auto writer = signedWriter(donorPath);
        REQUIRE(writer.addSignSeed(seedFromHex(otherSeedHex)));
        REQUIRE(writer.addBytes("a.txt", bytesOf("donor content")));
        REQUIRE(writer.finish());
    }

    auto bytes = readAll(path);
    REQUIRE(!bytes.empty());
    auto file = File::openRead(path);
    REQUIRE(file);
    auto reader = Reader::open(std::move(*file));
    REQUIRE(reader);
    REQUIRE(reader->hasSignatures());
    auto honest = reader->signatures().front().signature;

    // NOTE: a blind byte flip breaks the record checksum first, so the tampered file fails
    // NOTE: at open with Integrity, before any signature is used.
    auto forged = bytes;
    auto sigOffset = findOffset(forged, honest);
    REQUIRE(sigOffset != forged.size());
    forged[sigOffset] = static_cast<std::byte>(forged[sigOffset] ^ std::byte{0x01});
    {
        std::ofstream out(forgedPath, std::ios::binary | std::ios::trunc);
        REQUIRE(out);
        out.write(
            reinterpret_cast<const char*>(forged.data()),
            static_cast<std::streamsize>(forged.size())
        );
        REQUIRE(out);
    }
    auto forgedFile = File::openRead(forgedPath);
    REQUIRE(forgedFile);
    auto forgedReader = Reader::open(std::move(*forgedFile));
    REQUIRE_FALSE(forgedReader);
    CHECK(forgedReader.error().kind == ErrorKind::Integrity);

    // NOTE: transplanting a well-formed signature from another archive (with a repaired
    // NOTE: record checksum) still opens, but verification fails with Integrity: the bytes
    // NOTE: are valid, they are just not this commit's signature.
    auto donorFile = File::openRead(donorPath);
    REQUIRE(donorFile);
    auto donor = Reader::open(std::move(*donorFile));
    REQUIRE(donor);
    REQUIRE(donor->hasSignatures());
    auto transplant = bytes;
    RecordLimits scanLimits{
        .maxPayloadLength = std::uint64_t{256} << 20,
        .maxDecodedLength = std::uint64_t{256} << 20,
    };
    std::uint64_t trailerStart = transplant.size() - footerSize;
    std::uint64_t sigRecordAt = 0;
    bool foundRecord = false;
    for (std::size_t at = superblockSize; at + recordPrefixSize <= trailerStart; ++at) {
        if (!std::ranges::equal(
                std::span(transplant).subspan(at, recordMagic.size()),
                recordMagic
            )) {
            continue;
        }
        auto header = decodeRecordPrefix(
            std::span(transplant).subspan(at),
            scanLimits,
            static_cast<std::uint64_t>(at)
        );
        if (!header) {
            continue;
        }
        auto size = recordSize(header->payloadLength);
        if (!size) {
            continue;
        }
        if (header->type == RecordType::Extension &&
            static_cast<std::uint64_t>(at) + *size == trailerStart) {
            sigRecordAt = static_cast<std::uint64_t>(at);
            foundRecord = true;
            break;
        }
    }
    REQUIRE(foundRecord);
    std::size_t payloadAt = static_cast<std::size_t>(sigRecordAt + recordPrefixSize);
    auto donorSig = donor->signatures().front().signature;
    REQUIRE(transplant.size() >= payloadAt + 64 + recordTrailerSize);
    std::size_t sigValueAt = trailerStart - recordTrailerSize - donorSig.size();
    REQUIRE(sigValueAt >= payloadAt);
    std::ranges::copy(donorSig, transplant.begin() + static_cast<std::ptrdiff_t>(sigValueAt));
    auto freshCrc = Crc32c::of(
        std::span(transplant).subspan(payloadAt, trailerStart - recordTrailerSize - payloadAt)
    );
    storeLe(transplant.data() + trailerStart - recordTrailerSize, freshCrc);
    {
        std::ofstream out(transplantPath, std::ios::binary | std::ios::trunc);
        REQUIRE(out);
        out.write(
            reinterpret_cast<const char*>(transplant.data()),
            static_cast<std::streamsize>(transplant.size())
        );
        REQUIRE(out);
    }
    auto transplantFile = File::openRead(transplantPath);
    REQUIRE(transplantFile);
    auto transplantReader = Reader::open(std::move(*transplantFile));
    REQUIRE(transplantReader);
    REQUIRE(transplantReader->hasSignatures());
    std::vector<std::array<std::byte, 32>> good{pubFromHex(signerHex)};
    auto transplanted = transplantReader->verifySignatures(good);
    REQUIRE_FALSE(transplanted);
    CHECK(transplanted.error().kind == ErrorKind::Integrity);
    auto otherSeed = seedFromHex(otherSeedHex);
    auto otherPub = crypto::signPublicKeyOf(otherSeed.bytes());
    REQUIRE(otherPub);
    std::vector<std::array<std::byte, 32>> donorKey{*otherPub};
    auto donorReplay = transplantReader->verifySignatures(donorKey);
    REQUIRE_FALSE(donorReplay);
    CHECK(donorReplay.error().kind == ErrorKind::Integrity);

    // NOTE: flipping the signer length byte corrupts the TLV framing; with the record
    // NOTE: checksum repaired the archive still fails at open, now with a structural error
    // NOTE: from the signature decoder before any signature is used.
    auto broken = bytes;
    auto brokenSignerOffset = findOffset(broken, reader->signatures().front().signer);
    REQUIRE(brokenSignerOffset != broken.size());
    REQUIRE(brokenSignerOffset > 0);
    broken[brokenSignerOffset - 1] = std::byte{0x00};
    {
        auto header =
            decodeRecordPrefix(std::span(broken).subspan(sigRecordAt), scanLimits, sigRecordAt);
        REQUIRE(header);
        auto size = recordSize(header->payloadLength);
        REQUIRE(size);
        std::size_t brokenPayloadAt = static_cast<std::size_t>(sigRecordAt + recordPrefixSize);
        std::size_t brokenTrailerAt = static_cast<std::size_t>(sigRecordAt) +
            static_cast<std::size_t>(*size) - recordTrailerSize;
        auto brokenCrc = Crc32c::of(
            std::span(broken).subspan(brokenPayloadAt, brokenTrailerAt - brokenPayloadAt)
        );
        storeLe(broken.data() + brokenTrailerAt, brokenCrc);
    }
    {
        std::ofstream out(brokenPath, std::ios::binary | std::ios::trunc);
        REQUIRE(out);
        out.write(
            reinterpret_cast<const char*>(broken.data()),
            static_cast<std::streamsize>(broken.size())
        );
        REQUIRE(out);
    }
    auto brokenFile = File::openRead(brokenPath);
    REQUIRE(brokenFile);
    auto brokenReader = Reader::open(std::move(*brokenFile));
    REQUIRE_FALSE(brokenReader);
    CHECK(brokenReader.error().kind == ErrorKind::Malformed);
}

TEST_CASE("signing key files refuse bad inputs before touching the archive") {
    TempPath temp;
    std::filesystem::create_directories(temp.path());

    auto missing = loadSignSeeds((temp.path() / "nope.keys").string());
    REQUIRE_FALSE(missing);
    CHECK(missing.error().kind == ErrorKind::Io);

    auto badPath = temp.path() / "bad.keys";
    writeTextFile(badPath, "not hex at all\n");
    auto bad = loadSignSeeds(badPath.string());
    REQUIRE_FALSE(bad);
    CHECK(bad.error().kind == ErrorKind::Malformed);

    auto emptyPath = temp.path() / "empty.keys";
    writeTextFile(emptyPath, "# only a comment\n\n");
    auto empty = loadSignSeeds(emptyPath.string());
    REQUIRE_FALSE(empty);
    CHECK(empty.error().kind == ErrorKind::Malformed);

    auto manyPath = temp.path() / "many.keys";
    std::string many;
    for (std::size_t count = 0; count <= maxSignaturesPerCommit; ++count) {
        many += std::string(seedHex) + "\n";
    }
    writeTextFile(manyPath, many);
    auto manySeeds = loadSignSeeds(manyPath.string());
    REQUIRE_FALSE(manySeeds);
    CHECK(manySeeds.error().kind == ErrorKind::LimitExceeded);

    auto goodPath = temp.path() / "good.keys";
    writeTextFile(
        goodPath,
        "# two seeds\n" + std::string(seedHex) + "\n" + std::string(otherSeedHex) + "\n"
    );
    auto good = loadSignSeeds(goodPath.string());
    REQUIRE(good);
    CHECK(good->size() == 2);

    auto badVerify = parseVerifyKey("xyz");
    REQUIRE_FALSE(badVerify);
    auto goodVerify = parseVerifyKey(signerHex);
    REQUIRE(goodVerify);
    CHECK(*goodVerify == pubFromHex(signerHex));
}

TEST_CASE("signatures cover encrypted commits with epoch binding") {
    auto path = tempArchive("bale-sig-enc.bale");
    WriterOptions options = fixedOptions();
    options.experimentalEncryption = true;
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        auto secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addSignSeed(seedFromHex(seedHex)));
        REQUIRE(writer->addBytes("a.txt", bytesOf("secret content")));
        REQUIRE(writer->finish());
    }

    auto readFile = File::openRead(path);
    REQUIRE(readFile);
    auto reader = Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, testUnlock());
    REQUIRE(reader);
    CHECK(reader->epoch() == 1);
    REQUIRE(reader->hasSignatures());
    CHECK(reader->signatures().front().epoch == 1);
    std::vector<std::array<std::byte, 32>> good{pubFromHex(signerHex)};
    REQUIRE(reader->verifySignatures(good));
    REQUIRE(reader->verify(VerifyMode::Content));

    // NOTE: the encrypted signature is bound to epoch 1; replaying it at epoch 0 fails.
    auto seed = seedFromHex(seedHex);
    auto id = reader->superblock().archiveId;
    auto made = makeSignature(
        seed.bytes(),
        std::span<const std::byte, 16>(id.data(), 16),
        1,
        1,
        std::span<const std::byte, 32>(reader->commitDigest().data(), 32)
    );
    REQUIRE(made);
    auto replayed = checkSignature(
        *made,
        good.front(),
        std::span<const std::byte, 16>(id.data(), 16),
        1,
        0,
        std::span<const std::byte, 32>(reader->commitDigest().data(), 32)
    );
    REQUIRE_FALSE(replayed);
    CHECK(replayed.error().kind == ErrorKind::Integrity);

    std::error_code ignored;
    std::filesystem::remove(path, ignored);
}

TEST_CASE("compact of a signed encrypted archive refuses unless re-signed") {
    auto path = tempArchive("bale-sig-enc-compact.bale");
    auto flat = tempArchive("bale-sig-enc-flat.bale");
    auto resigned = tempArchive("bale-sig-enc-resigned.bale");
    WriterOptions encOptions = fixedOptions();
    encOptions.experimentalEncryption = true;
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        auto secrets = testWriterSecrets();
        auto writer = Writer::createEncrypted(std::move(*file), encOptions, std::move(secrets));
        REQUIRE(writer);
        REQUIRE(writer->addSignSeed(seedFromHex(seedHex)));
        REQUIRE(writer->addBytes("a.txt", bytesOf("secret compact")));
        REQUIRE(writer->finish());
    }

    std::vector<std::array<std::byte, 32>> good{pubFromHex(signerHex)};
    {
        auto file = File::openRead(path);
        REQUIRE(file);
        auto source = Reader::openEncrypted(std::move(*file), ReaderOptions{}, testUnlock());
        REQUIRE(source);
        auto out = File::createNew(flat);
        REQUIRE(out);
        auto compacted = Writer::compactEncrypted(std::move(*out), *source, false);
        REQUIRE_FALSE(compacted);
        CHECK(compacted.error().kind == ErrorKind::Malformed);
    }
    {
        auto file = File::openRead(path);
        REQUIRE(file);
        auto source = Reader::openEncrypted(std::move(*file), ReaderOptions{}, testUnlock());
        REQUIRE(source);
        auto out = File::createNew(resigned);
        REQUIRE(out);
        std::vector<crypto::SecretBytes> seeds;
        seeds.push_back(seedFromHex(seedHex));
        auto compacted =
            Writer::compactEncrypted(std::move(*out), *source, false, std::move(seeds));
        REQUIRE(compacted);
    }
    {
        auto file = File::openRead(resigned);
        REQUIRE(file);
        auto reader = Reader::openEncrypted(std::move(*file), ReaderOptions{}, testUnlock());
        REQUIRE(reader);
        REQUIRE(reader->verifySignatures(good));
        REQUIRE(reader->verify(VerifyMode::Content));
    }

    std::error_code removeIgnored;
    std::filesystem::remove(path, removeIgnored);
    std::filesystem::remove(flat, removeIgnored);
    std::filesystem::remove(resigned, removeIgnored);
}
