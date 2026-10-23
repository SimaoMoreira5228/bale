#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "cli/archive_commands.hpp"
#include "io/file.hpp"

#include "archive/encrypted_fixture.hpp"
#include "crypto/crypto_vectors.hpp"
#include "io/temp_file.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

using namespace bale;
using namespace bale::archive;
using bale::cli::ExitCode;

namespace {

WriterOptions cliParityOptions() {
    WriterOptions options;
    options.workers = 1;
    options.compression.codec = CodecId::Raw;
    options.parity.enabled = true;
    options.parity.dataShards = 2;
    options.parity.parityShards = 1;
    options.parity.shardBytes = 1024;
    std::array<std::byte, 16> id{};
    for (std::size_t index = 0; index < id.size(); ++index) {
        id[index] = static_cast<std::byte>(0x20 + index);
    }
    options.archiveId = id;
    options.creationTimeNanoseconds = 1700000000000000000;
    return options;
}

}

TEST_CASE("repair command verifies a healthy parity archive untouched") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "healthy.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), cliParityOptions());
        REQUIRE(writer);
        std::vector<std::byte> payload(3000, std::byte{0xAB});
        REQUIRE(writer->addBytes("blob", payload));
        REQUIRE(writer->finish());
    }
    CHECK(cli::repairArchive(path.string(), std::nullopt, {}) == ExitCode::Ok);
}

TEST_CASE("repair command fixes stripe damage and reports integrity failures") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto path = temp.path() / "damaged.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        auto writer = Writer::create(std::move(*file), cliParityOptions());
        REQUIRE(writer);
        std::vector<std::byte> payload(3000, std::byte{0xAB});
        REQUIRE(writer->addBytes("blob", payload));
        REQUIRE(writer->finish());
    }
    {
        auto file = File::openReadWrite(path);
        REQUIRE(file);
        std::array<std::byte, 1> byte{};
        REQUIRE(file->readExactAt(200, byte));
        byte[0] ^= std::byte{0xFF};
        REQUIRE(file->writeAt(200, byte));
    }
    CHECK(cli::testArchive(path.string(), std::nullopt, {}) == ExitCode::Integrity);
    CHECK(cli::repairArchive(path.string(), std::nullopt, {}) == ExitCode::Ok);
    CHECK(cli::testArchive(path.string(), std::nullopt, {}) == ExitCode::Ok);
}

TEST_CASE("repair command heals encrypted generations through a key file") {
    bale::test::TempPath temp;
    {
        std::error_code ignored;
        std::filesystem::create_directories(temp.path(), ignored);
    }
    auto pair = crypto::makeKeyPair();
    REQUIRE(pair);
    auto path = temp.path() / "enc.bale";
    {
        auto file = File::createNew(path);
        REQUIRE(file);
        WriterOptions options = cliParityOptions();
        options.experimentalEncryption = true;
        WriterSecrets secrets;
        secrets.recipientPublicKeys.push_back(pair->publicKey);
        auto writer = Writer::createEncrypted(std::move(*file), options, std::move(secrets));
        REQUIRE(writer);
        std::vector<std::byte> payload(3000, std::byte{0xCD});
        REQUIRE(writer->addBytes("blob", payload));
        REQUIRE(writer->finish());
    }
    auto keyFile = temp.path() / "keys.txt";
    {
        std::ofstream out(keyFile);
        REQUIRE(out.good());
        out << test::hexEncode(pair->secretKey.bytes()) << "\n";
    }
    CHECK(cli::repairArchive(path.string(), keyFile.string(), {}) == ExitCode::Ok);
    {
        auto file = File::openReadWrite(path);
        REQUIRE(file);
        std::array<std::byte, 1> byte{};
        REQUIRE(file->readExactAt(300, byte));
        byte[0] ^= std::byte{0xFF};
        REQUIRE(file->writeAt(300, byte));
    }
    CHECK(cli::repairArchive(path.string(), keyFile.string(), {}) == ExitCode::Ok);
    auto reader = Reader::openEncrypted(*File::openRead(path), ReaderOptions{}, [&]() {
        ReaderUnlock unlock;
        ReaderUnlock::RecipientKey key;
        key.publicKey = pair->publicKey;
        auto made = crypto::SecretBytes::make(pair->secretKey.size());
        REQUIRE(made);
        crypto::SecretBytes copy(std::move(*made));
        std::ranges::copy(pair->secretKey.bytes(), copy.mut().begin());
        key.secretKey = std::move(copy);
        unlock.recipients.push_back(std::move(key));
        return unlock;
    }());
    REQUIRE(reader);
    CHECK(reader->verify(VerifyMode::Content));
}
