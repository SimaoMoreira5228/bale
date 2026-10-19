#pragma once

#include "base/error.hpp"
#include "formats/sevenzip/header.hpp"
#include "io/byte_reader.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace bale::sevenzip {

constexpr std::uint8_t nidEnd = 0x00;
constexpr std::uint8_t nidHeader = 0x01;
constexpr std::uint8_t nidArchiveProperties = 0x02;
constexpr std::uint8_t nidAdditionalStreams = 0x03;
constexpr std::uint8_t nidMainStreams = 0x04;
constexpr std::uint8_t nidFilesInfo = 0x05;
constexpr std::uint8_t nidPackInfo = 0x06;
constexpr std::uint8_t nidUnpackInfo = 0x07;
constexpr std::uint8_t nidSubStreams = 0x08;
constexpr std::uint8_t nidSize = 0x09;
constexpr std::uint8_t nidCrc = 0x0A;
constexpr std::uint8_t nidFolder = 0x0B;
constexpr std::uint8_t nidCoderUnpackSize = 0x0C;
constexpr std::uint8_t nidNumUnpackStream = 0x0D;
constexpr std::uint8_t nidEmptyStream = 0x0E;
constexpr std::uint8_t nidEmptyFile = 0x0F;
constexpr std::uint8_t nidAnti = 0x10;
constexpr std::uint8_t nidName = 0x11;
constexpr std::uint8_t nidCTime = 0x12;
constexpr std::uint8_t nidATime = 0x13;
constexpr std::uint8_t nidMTime = 0x14;
constexpr std::uint8_t nidWinAttributes = 0x15;
constexpr std::uint8_t nidComment = 0x16;
constexpr std::uint8_t nidEncodedHeader = 0x17;
constexpr std::uint8_t nidStartPos = 0x18;
constexpr std::uint8_t nidDummy = 0x19;

[[nodiscard]] Result<std::uint64_t> readNumber(ByteReader& reader);

[[nodiscard]] Result<std::uint8_t> readId(ByteReader& reader);

[[nodiscard]] Result<void>
expectId(ByteReader& reader, std::uint8_t expected, std::string_view what);

[[nodiscard]] bool bitSet(std::span<const std::byte> bits, std::uint64_t index);

[[nodiscard]] Result<std::vector<std::byte>> readBits(ByteReader& reader, std::uint64_t count);

[[nodiscard]] Result<std::vector<std::optional<std::uint32_t>>>
readDigests(ByteReader& reader, std::uint64_t count, const Limits& limits);

[[nodiscard]] Result<void> skipProperties(ByteReader& reader, std::uint64_t offset);

[[nodiscard]] Result<std::uint64_t> folderOutputSize(const Folder& folder, std::uint64_t offset);

}
