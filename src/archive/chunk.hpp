#pragma once

#include "base/error.hpp"
#include "checksum/blake3.hpp"
#include "format/tlv.hpp"

#include <compare>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace bale::archive {

enum class HashAlgorithm : std::uint8_t {
    Blake3 = 1,
};

inline constexpr std::uint32_t minChunkSize = std::uint32_t{4} * 1024;
inline constexpr std::uint32_t defaultChunkSize = std::uint32_t{1} << 20;
inline constexpr std::uint32_t maxChunkSize = std::uint32_t{64} << 20;

inline constexpr std::uint32_t keyAlgorithmField = 1;
inline constexpr std::uint32_t keyDigestField = 2;
inline constexpr std::uint32_t keyLengthField = 3;

// NOTE: member order is the canonical index order: algorithm, digest bytes, then length.
struct ChunkKey {
    HashAlgorithm algorithm = HashAlgorithm::Blake3;
    Blake3Digest digest{};
    std::uint64_t length = 0;

    friend auto operator<=>(const ChunkKey&, const ChunkKey&) = default;
};

[[nodiscard]] ChunkKey chunkKeyOf(std::span<const std::byte> chunk);

[[nodiscard]] Result<void> writeChunkKey(TlvWriter& writer, const ChunkKey& key);

class ChunkKeyFields {
  public:
    [[nodiscard]] Result<bool> accept(const TlvField& field);

    [[nodiscard]] Result<ChunkKey> finish(std::uint64_t offset) const;

  private:
    ChunkKey key_;
    bool hasAlgorithm_ = false;
    bool hasDigest_ = false;
    bool hasLength_ = false;
};

[[nodiscard]] Result<ChunkKey>
decodeChunkKey(std::span<const std::byte> data, std::uint64_t offset);

inline constexpr std::size_t maxDataDescriptorSize = 128;

struct DataPayload {
    ChunkKey key;
    std::size_t descriptorSize = 0;
    std::span<const std::byte> encoded;
};

[[nodiscard]] Result<void> encodeDataDescriptor(const ChunkKey& key, std::vector<std::byte>& out);

[[nodiscard]] Result<DataPayload>
decodeDataPayload(std::span<const std::byte> payload, std::uint64_t offset);

}
