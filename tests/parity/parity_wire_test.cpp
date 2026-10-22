#include "archive/parity.hpp"

#include "archive/commit.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"

#include <doctest/doctest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace bale;
using namespace bale::archive;

namespace {

std::vector<std::byte> encodeHeaderBytes(const ParityHeader& header) {
    std::vector<std::byte> out;
    REQUIRE(encodeParityRecord(header, std::vector<std::byte>(header.shardBytes), out));
    return out;
}

ParityHeader testHeader() {
    ParityHeader header;
    header.groupId = 0x1122334455667788;
    header.generation = 3;
    header.stripeIndex = 5;
    header.shardIndex = 10;
    header.dataShards = 10;
    header.parityShards = 4;
    header.shardBytes = 16;
    header.stripeCount = 8;
    header.streamLength = 8 * 10 * 16 - 7;
    header.crc.assign(14, 0xA5A5A5A5);
    return header;
}

}

TEST_CASE("parity wire values are provisional and fail old readers closed") {
    CHECK(static_cast<std::uint8_t>(RecordType::Parity) == 6);
    CHECK(parityRecordFlag == 0x0002);
    CHECK((knownRequiredRecordFlags & parityRecordFlag) != 0);
    CHECK(parityRequiredFeature == 0x00000002);
    CHECK((knownRequiredFeatures & parityRequiredFeature) != 0);
    CHECK(parityCommitFeature == 0x00000002);
    CHECK((knownCommitFeatures & parityCommitFeature) != 0);
    CHECK(parityRecordVersion == 1);
}

TEST_CASE("parity spec parsing accepts named presets and explicit pairs only") {
    auto small = parseParitySpec("small");
    REQUIRE(small);
    CHECK(small->enabled);
    CHECK(small->dataShards == 10);
    CHECK(small->parityShards == 4);

    auto capacity = parseParitySpec("capacity");
    REQUIRE(capacity);
    CHECK(capacity->dataShards == 17);
    CHECK(capacity->parityShards == 3);

    auto explicitPair = parseParitySpec("4+2");
    REQUIRE(explicitPair);
    CHECK(explicitPair->dataShards == 4);
    CHECK(explicitPair->parityShards == 2);

    auto zeroData = parseParitySpec("0+4");
    REQUIRE(zeroData);
    CHECK_FALSE(validateParityConfig(*zeroData));

    auto zeroParity = parseParitySpec("4+0");
    REQUIRE(zeroParity);
    CHECK_FALSE(validateParityConfig(*zeroParity));

    CHECK_FALSE(parseParitySpec("xor"));
    CHECK_FALSE(parseParitySpec("10"));
    CHECK_FALSE(parseParitySpec("10+"));
    CHECK_FALSE(parseParitySpec("+4"));
    CHECK_FALSE(parseParitySpec("1000+4"));
}

TEST_CASE("parity config validation enforces the field and policy bounds") {
    ParityConfig good;
    good.enabled = true;
    CHECK(validateParityConfig(good));

    ParityConfig disabled;
    CHECK(validateParityConfig(disabled));

    ParityConfig zeroData = good;
    zeroData.dataShards = 0;
    CHECK_FALSE(validateParityConfig(zeroData));

    ParityConfig zeroParity = good;
    zeroParity.parityShards = 0;
    CHECK_FALSE(validateParityConfig(zeroParity));

    ParityConfig tooMany = good;
    tooMany.dataShards = 200;
    tooMany.parityShards = 100;
    CHECK(tooMany.dataShards + tooMany.parityShards > 256);
    CHECK_FALSE(validateParityConfig(tooMany));
    CHECK(validateParityConfig(tooMany).error().kind == ErrorKind::LimitExceeded);

    ParityConfig tiny = good;
    tiny.shardBytes = 512;
    CHECK_FALSE(validateParityConfig(tiny));

    ParityConfig huge = good;
    huge.shardBytes = (std::uint32_t{1} << 20) + 1;
    CHECK_FALSE(validateParityConfig(huge));

    ParityConfig fat = good;
    fat.dataShards = 255;
    fat.parityShards = 1;
    fat.shardBytes = (std::uint32_t{1} << 20);
    CHECK(validateParityConfig(fat));
}

TEST_CASE("parity stripe counts divide the stream with a zero-padded tail") {
    CHECK(stripeCountFor(1, 10, 65536).value_or(0) == 1);
    CHECK(stripeCountFor(10 * 65536ULL, 10, 65536).value_or(0) == 1);
    CHECK(stripeCountFor(10 * 65536ULL + 1, 10, 65536).value_or(0) == 2);
    CHECK_FALSE(stripeCountFor(0, 10, 65536));
    CHECK_FALSE(stripeCountFor(100, 0, 65536));

    auto pairConfig = parseParitySpec("4+2").value();
    pairConfig.shardBytes = 1024;
    auto descriptor = makeParityDescriptor(pairConfig, 9000, 77);
    REQUIRE(descriptor);
    CHECK(descriptor->present);
    CHECK(descriptor->dataShards == 4);
    CHECK(descriptor->parityShards == 2);
    CHECK(descriptor->stripeCount == 3);
    CHECK(descriptor->groupId == 77);
    CHECK_FALSE(makeParityDescriptor(parseParitySpec("4+2").value(), 9000, 0));
}

TEST_CASE("parity record layout is byte-exact little-endian") {
    auto header = testHeader();
    std::vector<std::byte> shard(16, std::byte{0x5A});
    std::vector<std::byte> out;
    REQUIRE(encodeParityRecord(header, shard, out));
    REQUIRE(out.size() == 60 + 14 * 4 + 16);

    CHECK(loadLe<std::uint32_t>(out.data()) == 1);
    CHECK(loadLe<std::uint64_t>(out.data() + 4) == 0x1122334455667788);
    CHECK(loadLe<std::uint64_t>(out.data() + 12) == 3);
    CHECK(loadLe<std::uint64_t>(out.data() + 20) == 5);
    CHECK(loadLe<std::uint32_t>(out.data() + 28) == 10);
    CHECK(loadLe<std::uint32_t>(out.data() + 32) == 10);
    CHECK(loadLe<std::uint32_t>(out.data() + 36) == 4);
    CHECK(loadLe<std::uint32_t>(out.data() + 40) == 16);
    CHECK(loadLe<std::uint64_t>(out.data() + 44) == 8);
    CHECK(loadLe<std::uint64_t>(out.data() + 52) == 8 * 10 * 16 - 7);
    for (std::uint32_t index = 0; index < 14; ++index) {
        CHECK(
            loadLe<std::uint32_t>(out.data() + 60 + static_cast<std::size_t>(index) * 4) ==
            0xA5A5A5A5
        );
    }
    CHECK(std::ranges::equal(std::span(out).subspan(60 + 14 * 4), std::span(shard)));

    auto decoded = decodeParityRecord(out, 1000);
    REQUIRE(decoded);
    CHECK(decoded->groupId == header.groupId);
    CHECK(decoded->generation == header.generation);
    CHECK(decoded->stripeIndex == header.stripeIndex);
    CHECK(decoded->shardIndex == header.shardIndex);
    CHECK(decoded->dataShards == 10);
    CHECK(decoded->parityShards == 4);
    CHECK(decoded->shardBytes == 16);
    CHECK(decoded->stripeCount == 8);
    CHECK(decoded->streamLength == header.streamLength);
    CHECK(decoded->crc == header.crc);
}

TEST_CASE("parity record decoding rejects hostile shapes before use") {
    auto header = testHeader();
    auto good = encodeHeaderBytes(header);

    for (std::size_t size = 0; size < good.size(); ++size) {
        CAPTURE(size);
        CHECK_FALSE(decodeParityRecord(std::span(good).first(size), 0));
    }

    auto badVersion = good;
    storeLe(badVersion.data(), std::uint32_t{2});
    CHECK(decodeParityRecord(badVersion, 0).error().kind == ErrorKind::Unsupported);

    auto dataShard = good;
    storeLe(dataShard.data() + 28, std::uint32_t{3});
    CHECK_FALSE(decodeParityRecord(dataShard, 0));

    auto overIndex = good;
    storeLe(overIndex.data() + 28, std::uint32_t{14});
    CHECK_FALSE(decodeParityRecord(overIndex, 0));

    auto overStripe = good;
    storeLe(overStripe.data() + 20, std::uint64_t{8});
    CHECK_FALSE(decodeParityRecord(overStripe, 0));

    auto zeroGroup = good;
    storeLe(zeroGroup.data() + 4, std::uint64_t{0});
    CHECK_FALSE(decodeParityRecord(zeroGroup, 0));

    auto zeroStream = good;
    storeLe(zeroStream.data() + 52, std::uint64_t{0});
    CHECK_FALSE(decodeParityRecord(zeroStream, 0));

    auto longStream = good;
    storeLe(longStream.data() + 52, std::uint64_t{8} * 10 * 16 + 1);
    CHECK_FALSE(decodeParityRecord(longStream, 0));

    auto shortStream = good;
    storeLe(shortStream.data() + 52, std::uint64_t{7} * 10 * 16);
    CHECK_FALSE(decodeParityRecord(shortStream, 0));

    ParityHeader shortCrc = header;
    shortCrc.crc.assign(5, 1);
    std::vector<std::byte> shortOut;
    CHECK_FALSE(encodeParityRecord(shortCrc, std::vector<std::byte>(16), shortOut));

    std::vector<std::byte> wrongShard(15, std::byte{0});
    std::vector<std::byte> wrongOut;
    CHECK_FALSE(encodeParityRecord(header, wrongShard, wrongOut));
}

TEST_CASE("parity footer descriptor round-trips and zero means absent") {
    Footer plain;
    plain.commitOffset = superblockSize;
    plain.commitLength = recordFramingSize;
    plain.generation = 1;
    auto encodedPlain = encodeFooter(plain);
    auto decodedPlain = decodeFooter(encodedPlain, superblockSize + recordFramingSize);
    REQUIRE(decodedPlain);
    CHECK_FALSE(decodedPlain->parity.present);

    Footer footer;
    footer.commitOffset = 128;
    footer.commitLength = 256;
    footer.generation = 2;
    footer.commitDigest.fill(std::byte{0x11});
    footer.parity.present = true;
    footer.parity.dataShards = 10;
    footer.parity.parityShards = 4;
    footer.parity.shardBytes = 65536;
    footer.parity.stripeCount = 9;
    footer.parity.groupId = 12345;
    auto encoded = encodeFooter(footer);
    auto decoded = decodeFooter(encoded, 8192);
    REQUIRE(decoded);
    CHECK(decoded->parity.present);
    CHECK(decoded->parity.dataShards == 10);
    CHECK(decoded->parity.parityShards == 4);
    CHECK(decoded->parity.shardBytes == 65536);
    CHECK(decoded->parity.stripeCount == 9);
    CHECK(decoded->parity.groupId == 12345);
    CHECK(decoded->commitOffset == 128);
    CHECK(decoded->generation == 2);

    auto tampered = encoded;
    tampered[68] = std::byte{0xFF};
    tampered[69] = std::byte{0xFF};
    tampered[70] = std::byte{0xFF};
    tampered[71] = std::byte{0xFF};
    CHECK_FALSE(decodeFooter(tampered, 8192));

    ParityDescriptor descriptor;
    descriptor.present = true;
    descriptor.dataShards = 10;
    descriptor.parityShards = 4;
    descriptor.shardBytes = 65536;
    descriptor.stripeCount = 9;
    descriptor.groupId = 12345;
    Footer any;
    CHECK(checkParityHeader(testHeader(), descriptor, 3, 0).error().kind == ErrorKind::Integrity);

    ParityDescriptor matching;
    matching.present = true;
    matching.dataShards = 10;
    matching.parityShards = 4;
    matching.shardBytes = 16;
    matching.stripeCount = 8;
    matching.groupId = 0x1122334455667788;
    CHECK(checkParityHeader(testHeader(), matching, 3, 0));

    ParityDescriptor absent;
    CHECK(checkParityHeader(testHeader(), absent, 3, 0).error().kind == ErrorKind::Malformed);
}
