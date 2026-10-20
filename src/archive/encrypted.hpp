#pragma once

#include "archive/chunk.hpp"
#include "archive/commit.hpp"
#include "base/error.hpp"
#include "crypto/crypto.hpp"
#include "crypto/secrets.hpp"
#include "format/record.hpp"
#include "io/file.hpp"
#include "security/budget.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace bale::archive {

// NOTE: all numeric wire values below are provisional experimental allocations. The native
// NOTE: format is unfrozen; later builds may not read archives using them.

inline constexpr std::uint32_t keyslotExtensionKind = 1;
inline constexpr std::uint64_t keyslotVersion = 1;
inline constexpr std::uint64_t encryptedCommitEpochField = 13;
inline constexpr std::size_t encryptedObjectIdSize = 32;
inline constexpr std::size_t encryptedDataHeaderSize = 64;
inline constexpr std::size_t encryptedMetaNonceSize = 24;
inline constexpr std::uint64_t maxKeyslotsPerArchive = 64;
inline constexpr std::uint64_t maxEncryptedPayloadBytes = std::uint64_t{64} << 20;

using ObjectId = std::array<std::byte, encryptedObjectIdSize>;

enum class SlotKind : std::uint8_t {
    Password = 0,
    Recipient = 1,
};

struct Keyslot {
    std::uint64_t epoch = 0;
    SlotKind kind = SlotKind::Password;
    std::array<std::byte, crypto::saltSize> salt{};
    std::uint64_t opslimit = 0;
    std::size_t memlimitBytes = 0;
    std::array<std::byte, crypto::nonceSize> nonce{};
    std::vector<std::byte> wrapped;
    std::array<std::byte, crypto::publicKeySize> recipientPublic{};
    std::vector<std::byte> sealed;
};

struct EncryptedExtent {
    ChunkKey plain;
    ObjectId object{};
};

[[nodiscard]] Result<void> encodeKeyslot(const Keyslot& slot, std::vector<std::byte>& out);

[[nodiscard]] Result<Keyslot>
decodeKeyslot(std::span<const std::byte> payload, std::uint64_t offset);

[[nodiscard]] Result<void>
encodeEncryptedChunkKey(const ChunkKey& plain, const ObjectId& object, std::vector<std::byte>& out);

[[nodiscard]] Result<EncryptedExtent>
decodeEncryptedExtent(std::span<const std::byte> data, std::uint64_t offset);

[[nodiscard]] std::vector<std::byte> dataAad(
    std::span<const std::byte, 16> archiveId,
    const ObjectId& object,
    CodecId codec,
    std::uint64_t epoch
);

[[nodiscard]] std::vector<std::byte>
manifestAad(std::span<const std::byte, 16> archiveId, std::uint64_t epoch);

[[nodiscard]] std::vector<std::byte>
indexAad(std::span<const std::byte, 16> archiveId, std::uint64_t epoch);

[[nodiscard]] std::vector<std::byte>
commitAad(std::span<const std::byte, 16> archiveId, std::uint64_t epoch);

[[nodiscard]] Result<ObjectId> makeObjectId();

[[nodiscard]] Result<std::array<std::byte, crypto::nonceSize>> makeRecordNonce();

struct ReaderUnlock;

[[nodiscard]] Result<std::map<std::uint64_t, crypto::SecretBytes>>
collectDataKeys(File& file, std::uint64_t fileSize, ReaderUnlock& unlock, const Limits& limits);

}
