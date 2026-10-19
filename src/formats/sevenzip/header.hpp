#pragma once

#include "base/error.hpp"
#include "io/byte_reader.hpp"
#include "io/file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace bale::sevenzip {

inline constexpr std::size_t signatureSize = 32;

inline constexpr std::array<std::byte, 6> signatureMagic{
    std::byte{'7'},
    std::byte{'z'},
    std::byte{0xBC},
    std::byte{0xAF},
    std::byte{0x27},
    std::byte{0x1C},
};

struct Limits {
    std::uint64_t maxEntries = 1'000'000;
    std::uint64_t maxHeaderBytes = std::uint64_t{256} << 20;
    std::uint64_t maxFolders = 1'000'000;
    std::uint64_t maxFolderBytes = std::uint64_t{1} << 40;
    std::uint64_t maxEntryBytes = std::uint64_t{1} << 38;
    std::uint64_t decoderMemLimitBytes = std::uint64_t{256} << 20;
    std::size_t maxNameBytes = 4096;
};

struct Signature {
    std::uint64_t headerOffset = 0;
    std::uint64_t headerSize = 0;
    std::vector<std::byte> bytes;
};

[[nodiscard]] Result<Signature> readSignature(const File& file, const Limits& limits);

struct PackStream {
    std::uint64_t size = 0;
    std::optional<std::uint32_t> crc;
};

struct Coder {
    std::vector<std::uint8_t> id;
    std::vector<std::byte> props;
    std::uint64_t inStreams = 1;
    std::uint64_t outStreams = 1;
};

struct BindPair {
    std::uint64_t inIndex = 0;
    std::uint64_t outIndex = 0;
};

struct Folder {
    std::vector<Coder> coders;
    std::vector<BindPair> binds;
    std::vector<std::uint64_t> packedStreams;
    std::uint64_t numInStreams = 0;
    std::uint64_t numOutStreams = 0;
    std::uint64_t numPackedStreams = 0;
    std::uint64_t finalOutStream = 0;
    std::vector<std::uint64_t> unpackSizes;
    std::optional<std::uint32_t> crc;
};

struct SubStream {
    std::uint64_t size = 0;
    std::optional<std::uint32_t> crc;
};

struct FileMeta {
    std::string name;
    bool hasStream = true;
    bool emptyFile = false;
    bool anti = false;
    std::optional<std::uint64_t> startPos;
    std::optional<std::int64_t> mtimeNanoseconds;
    std::optional<std::uint32_t> mode;
};

struct Model {
    std::uint64_t packPos = 0;
    std::vector<PackStream> packs;
    std::vector<Folder> folders;
    std::vector<std::vector<SubStream>> substreams;
    std::vector<FileMeta> files;
    bool hasStreams = false;
};

[[nodiscard]] Result<Model>
parseHeader(std::span<const std::byte> bytes, std::uint64_t baseOffset, const Limits& limits);

[[nodiscard]] Result<void> readFilesInfo(ByteReader& reader, Model& model, const Limits& limits);

}
