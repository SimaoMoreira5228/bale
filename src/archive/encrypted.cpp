#include "archive/encrypted.hpp"

#include "archive/signatures.hpp"
#include "archive/writer.hpp"
#include "base/checked.hpp"
#include "base/endian.hpp"
#include "crypto/crypto.hpp"
#include "format/envelope.hpp"
#include "format/record.hpp"
#include "format/tlv.hpp"

#include <algorithm>
#include <map>
#include <string_view>

namespace bale::archive {

namespace {

constexpr std::uint32_t extKindField = 1;
constexpr std::uint32_t extVersionField = 2;
constexpr std::uint32_t extEpochField = 3;
constexpr std::uint32_t extSlotKindField = 4;
constexpr std::uint32_t extSaltField = 10;
constexpr std::uint32_t extOpsField = 11;
constexpr std::uint32_t extMemField = 12;
constexpr std::uint32_t extNonceField = 13;
constexpr std::uint32_t extWrappedField = 14;
constexpr std::uint32_t extRecipientPubField = 20;
constexpr std::uint32_t extSealedField = 21;

constexpr std::string_view dataDomain = "bale-enc-v1/data";
constexpr std::string_view manifestDomain = "bale-enc-v1/manifest";
constexpr std::string_view indexDomain = "bale-enc-v1/index";
constexpr std::string_view commitDomain = "bale-enc-v1/commit";

void appendU32Le(std::vector<std::byte>& out, std::uint32_t value) {
    std::array<std::byte, 4> encoded{};
    storeLe(encoded.data(), value);
    out.insert(out.end(), encoded.begin(), encoded.end());
}

void appendU64Le(std::vector<std::byte>& out, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    storeLe(encoded.data(), value);
    out.insert(out.end(), encoded.begin(), encoded.end());
}

}

Result<void> encodeKeyslot(const Keyslot& slot, std::vector<std::byte>& out) {
    out.clear();
    if (slot.epoch == 0) {
        return fail(ErrorKind::Malformed, "keyslot epoch is zero");
    }
    TlvWriter writer(out);
    auto kind = writer.unsignedValue(extKindField, Criticality::Critical, keyslotExtensionKind);
    if (!kind) {
        return kind;
    }
    auto version = writer.unsignedValue(extVersionField, Criticality::Critical, keyslotVersion);
    if (!version) {
        return version;
    }
    auto epoch = writer.unsignedValue(extEpochField, Criticality::Critical, slot.epoch);
    if (!epoch) {
        return epoch;
    }
    auto slotKind = writer.unsignedValue(
        extSlotKindField,
        Criticality::Critical,
        static_cast<std::uint64_t>(slot.kind)
    );
    if (!slotKind) {
        return slotKind;
    }
    if (slot.kind == SlotKind::Password) {
        auto salt = writer.bytes(extSaltField, Criticality::Critical, slot.salt);
        if (!salt) {
            return salt;
        }
        auto ops = writer.unsignedValue(extOpsField, Criticality::Critical, slot.opslimit);
        if (!ops) {
            return ops;
        }
        auto mem = writer.unsignedValue(extMemField, Criticality::Critical, slot.memlimitBytes);
        if (!mem) {
            return mem;
        }
        auto nonce = writer.bytes(extNonceField, Criticality::Critical, slot.nonce);
        if (!nonce) {
            return nonce;
        }
        return writer.bytes(extWrappedField, Criticality::Critical, slot.wrapped);
    }
    auto pub = writer.bytes(extRecipientPubField, Criticality::Critical, slot.recipientPublic);
    if (!pub) {
        return pub;
    }
    return writer.bytes(extSealedField, Criticality::Critical, slot.sealed);
}

Result<Keyslot> decodeKeyslot(std::span<const std::byte> payload, std::uint64_t offset) {
    Keyslot slot;
    bool hasKind = false;
    bool hasVersion = false;
    bool hasEpoch = false;
    bool hasSlotKind = false;
    bool hasSalt = false;
    bool hasOps = false;
    bool hasMem = false;
    bool hasNonce = false;
    bool hasWrapped = false;
    bool hasPub = false;
    bool hasSealed = false;

    TlvReader reader(payload, offset);
    TlvField field;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return tl::unexpected<Error>(more.error());
        }
        if (!*more) {
            break;
        }
        if (field.number > extSealedField) {
            auto skipped = skipUnknownField(field);
            if (!skipped) {
                return tl::unexpected<Error>(skipped.error());
            }
            continue;
        }
        // NOTE: unknown noncritical fields are skipped; unknown critical fields fail.
        bool known = field.number == extKindField || field.number == extVersionField ||
            field.number == extEpochField || field.number == extSlotKindField ||
            field.number == extSaltField || field.number == extOpsField ||
            field.number == extMemField || field.number == extNonceField ||
            field.number == extWrappedField || field.number == extRecipientPubField ||
            field.number == extSealedField;
        if (!known) {
            auto skipped = skipUnknownField(field);
            if (!skipped) {
                return tl::unexpected<Error>(skipped.error());
            }
            continue;
        }
        auto critical = requireCriticality(field, Criticality::Critical);
        if (!critical) {
            return tl::unexpected<Error>(critical.error());
        }
        switch (field.number) {
        case extKindField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return tl::unexpected<Error>(value.error());
            }
            if (*value != keyslotExtensionKind) {
                return fail(ErrorKind::Unsupported, "unknown extension kind", field.offset);
            }
            hasKind = true;
            break;
        }
        case extVersionField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return tl::unexpected<Error>(value.error());
            }
            if (*value != keyslotVersion) {
                return fail(ErrorKind::Unsupported, "unsupported keyslot version", field.offset);
            }
            hasVersion = true;
            break;
        }
        case extEpochField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return tl::unexpected<Error>(value.error());
            }
            if (*value == 0) {
                return fail(ErrorKind::Malformed, "keyslot epoch is zero", field.offset);
            }
            slot.epoch = *value;
            hasEpoch = true;
            break;
        }
        case extSlotKindField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return tl::unexpected<Error>(value.error());
            }
            if (*value != static_cast<std::uint64_t>(SlotKind::Password) &&
                *value != static_cast<std::uint64_t>(SlotKind::Recipient)) {
                return fail(ErrorKind::Malformed, "unknown slot kind", field.offset);
            }
            slot.kind = static_cast<SlotKind>(*value);
            hasSlotKind = true;
            break;
        }
        case extSaltField:
            if (field.value.size() != crypto::saltSize) {
                return fail(ErrorKind::Malformed, "keyslot salt has a bad size", field.offset);
            }
            std::ranges::copy(field.value, slot.salt.begin());
            hasSalt = true;
            break;
        case extOpsField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return tl::unexpected<Error>(value.error());
            }
            if (*value == 0) {
                return fail(ErrorKind::Malformed, "keyslot opslimit is zero", field.offset);
            }
            // NOTE: reject over-cap params at the TLV layer, before any KDF allocation.
            if (*value > crypto::maxSlotOpslimit) {
                return fail(
                    ErrorKind::LimitExceeded,
                    "keyslot opslimit exceeds the bale ceiling",
                    field.offset
                );
            }
            slot.opslimit = *value;
            hasOps = true;
            break;
        }
        case extMemField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return tl::unexpected<Error>(value.error());
            }
            if (*value == 0) {
                return fail(ErrorKind::Malformed, "keyslot memlimit is zero", field.offset);
            }
            // NOTE: reject over-cap params at the TLV layer, before any KDF allocation.
            if (*value > crypto::maxSlotMemlimitBytes) {
                return fail(
                    ErrorKind::LimitExceeded,
                    "keyslot memlimit exceeds the bale ceiling",
                    field.offset
                );
            }
            slot.memlimitBytes = static_cast<std::size_t>(*value);
            hasMem = true;
            break;
        }
        case extNonceField:
            if (field.value.size() != crypto::nonceSize) {
                return fail(ErrorKind::Malformed, "keyslot nonce has a bad size", field.offset);
            }
            std::ranges::copy(field.value, slot.nonce.begin());
            hasNonce = true;
            break;
        case extWrappedField:
            if (field.value.size() != crypto::keySize + crypto::tagSize) {
                return fail(ErrorKind::Malformed, "keyslot wrap has a bad size", field.offset);
            }
            slot.wrapped.assign(field.value.begin(), field.value.end());
            hasWrapped = true;
            break;
        case extRecipientPubField:
            if (field.value.size() != crypto::publicKeySize) {
                return fail(ErrorKind::Malformed, "recipient key has a bad size", field.offset);
            }
            std::ranges::copy(field.value, slot.recipientPublic.begin());
            hasPub = true;
            break;
        case extSealedField:
            if (field.value.size() != crypto::keySize + crypto::sealOverhead) {
                return fail(ErrorKind::Malformed, "recipient seal has a bad size", field.offset);
            }
            slot.sealed.assign(field.value.begin(), field.value.end());
            hasSealed = true;
            break;
        default:
            return fail(ErrorKind::Malformed, "unreachable keyslot field", field.offset);
        }
    }

    if (!hasKind || !hasVersion || !hasEpoch || !hasSlotKind) {
        return fail(ErrorKind::Malformed, "keyslot missing a required field", offset);
    }
    if (slot.kind == SlotKind::Password) {
        if (!hasSalt || !hasOps || !hasMem || !hasNonce || !hasWrapped) {
            return fail(ErrorKind::Malformed, "password slot missing a field", offset);
        }
        if (hasPub || hasSealed) {
            return fail(ErrorKind::Malformed, "password slot has recipient fields", offset);
        }
    } else {
        if (!hasPub || !hasSealed) {
            return fail(ErrorKind::Malformed, "recipient slot missing a field", offset);
        }
        if (hasSalt || hasOps || hasMem || hasNonce || hasWrapped) {
            return fail(ErrorKind::Malformed, "recipient slot has password fields", offset);
        }
    }
    return slot;
}

Result<void> encodeEncryptedChunkKey(
    const ChunkKey& plain,
    const ObjectId& object,
    std::vector<std::byte>& out
) {
    out.clear();
    TlvWriter writer(out);
    auto written = writeChunkKey(writer, plain);
    if (!written) {
        return written;
    }
    return writer.bytes(10, Criticality::Critical, object);
}

Result<EncryptedExtent>
decodeEncryptedExtent(std::span<const std::byte> data, std::uint64_t offset) {
    EncryptedExtent extent;
    ChunkKeyFields keyFields;
    bool hasObject = false;
    TlvReader reader(data, offset);
    TlvField field;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return tl::unexpected<Error>(more.error());
        }
        if (!*more) {
            break;
        }
        if (field.number == 10) {
            auto critical = requireCriticality(field, Criticality::Critical);
            if (!critical) {
                return tl::unexpected<Error>(critical.error());
            }
            if (field.value.size() != encryptedObjectIdSize) {
                return fail(ErrorKind::Malformed, "object id has a bad size", field.offset);
            }
            std::ranges::copy(field.value, extent.object.begin());
            hasObject = true;
            continue;
        }
        auto accepted = keyFields.accept(field);
        if (!accepted) {
            return tl::unexpected<Error>(accepted.error());
        }
        if (*accepted) {
            continue;
        }
        auto skipped = skipUnknownField(field);
        if (!skipped) {
            return tl::unexpected<Error>(skipped.error());
        }
    }
    auto key = keyFields.finish(offset);
    if (!key) {
        return tl::unexpected<Error>(key.error());
    }
    if (!hasObject) {
        return fail(ErrorKind::Malformed, "encrypted extent missing object id", offset);
    }
    extent.plain = *key;
    return extent;
}

std::vector<std::byte> dataAad(
    std::span<const std::byte, 16> archiveId,
    const ObjectId& object,
    CodecId codec,
    std::uint64_t epoch
) {
    std::vector<std::byte> out;
    out.reserve(dataDomain.size() + 16 + 32 + 4 + 8);
    out.insert(
        out.end(),
        reinterpret_cast<const std::byte*>(dataDomain.data()),
        reinterpret_cast<const std::byte*>(dataDomain.data() + dataDomain.size())
    );
    out.insert(out.end(), archiveId.begin(), archiveId.end());
    out.insert(out.end(), object.begin(), object.end());
    appendU32Le(out, static_cast<std::uint32_t>(codec));
    appendU64Le(out, epoch);
    return out;
}

std::vector<std::byte> manifestAad(std::span<const std::byte, 16> archiveId, std::uint64_t epoch) {
    std::vector<std::byte> out;
    out.reserve(manifestDomain.size() + 16 + 8);
    out.insert(
        out.end(),
        reinterpret_cast<const std::byte*>(manifestDomain.data()),
        reinterpret_cast<const std::byte*>(manifestDomain.data() + manifestDomain.size())
    );
    out.insert(out.end(), archiveId.begin(), archiveId.end());
    appendU64Le(out, epoch);
    return out;
}

std::vector<std::byte> indexAad(std::span<const std::byte, 16> archiveId, std::uint64_t epoch) {
    std::vector<std::byte> out;
    out.reserve(indexDomain.size() + 16 + 8);
    out.insert(
        out.end(),
        reinterpret_cast<const std::byte*>(indexDomain.data()),
        reinterpret_cast<const std::byte*>(indexDomain.data() + indexDomain.size())
    );
    out.insert(out.end(), archiveId.begin(), archiveId.end());
    appendU64Le(out, epoch);
    return out;
}

std::vector<std::byte> commitAad(std::span<const std::byte, 16> archiveId, std::uint64_t epoch) {
    std::vector<std::byte> out;
    out.reserve(commitDomain.size() + 16 + 8);
    out.insert(
        out.end(),
        reinterpret_cast<const std::byte*>(commitDomain.data()),
        reinterpret_cast<const std::byte*>(commitDomain.data() + commitDomain.size())
    );
    out.insert(out.end(), archiveId.begin(), archiveId.end());
    appendU64Le(out, epoch);
    return out;
}

Result<ObjectId> makeObjectId() {
    auto nonce = crypto::makeNonce();
    if (!nonce) {
        return tl::unexpected<Error>(nonce.error());
    }
    // NOTE: 32 random bytes from two 24-byte nonces would leak structure; instead build from
    // NOTE: libsodium directly through two independent keys is overkill. Use makeKey randomness.
    auto key = crypto::makeKey();
    if (!key) {
        return tl::unexpected<Error>(key.error());
    }
    ObjectId id{};
    std::ranges::copy(key->bytes(), id.begin());
    return id;
}

Result<std::array<std::byte, crypto::nonceSize>> makeRecordNonce() {
    return crypto::makeNonce();
}

Result<std::map<std::uint64_t, crypto::SecretBytes>>
collectDataKeys(File& file, std::uint64_t fileSize, ReaderUnlock& unlock, const Limits& limits) {
    std::map<std::uint64_t, crypto::SecretBytes> keys;
    std::vector<std::byte> recordBuffer;
    std::uint64_t position = superblockSize;
    std::uint64_t slotsSeen = 0;
    RecordLimits recordLimits{
        .maxPayloadLength = maxEncryptedPayloadBytes,
        .maxDecodedLength = maxEncryptedPayloadBytes,
    };
    std::array<std::byte, recordPrefixSize> prefix{};
    std::array<std::byte, footerSize> footerBytes{};
    (void)limits;
    while (position < fileSize) {
        if (fileSize - position >= footerSize) {
            auto peek = file.readExactAt(position, std::span<std::byte>(footerBytes));
            if (!peek) {
                return tl::unexpected<Error>(peek.error());
            }
            if (std::ranges::equal(std::span(footerBytes).first(footerMagic.size()), footerMagic)) {
                auto footer = decodeFooter(footerBytes, position);
                if (footer) {
                    position += footerSize;
                    continue;
                }
            }
        }
        if (fileSize - position < recordFramingSize) {
            break;
        }
        auto read = file.readExactAt(position, std::span<std::byte>(prefix));
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        auto header = decodeRecordPrefix(prefix, recordLimits, position);
        if (!header) {
            break;
        }
        auto size = recordSize(header->payloadLength);
        if (!size || !fitsWithin(position, *size, fileSize)) {
            break;
        }
        if (header->type != RecordType::Extension || (header->flags & encryptedRecordFlag) == 0) {
            position += *size;
            continue;
        }
        if (header->payloadLength > 4096) {
            return fail(ErrorKind::LimitExceeded, "keyslot payload too large", position);
        }
        recordBuffer.resize(static_cast<std::size_t>(*size));
        auto full = file.readExactAt(position, recordBuffer);
        if (!full) {
            return tl::unexpected<Error>(full.error());
        }
        auto record = decodeRecord(recordBuffer, recordLimits, position);
        if (!record) {
            return tl::unexpected<Error>(record.error());
        }
        // NOTE: SIGNATURE records share the Extension type; they carry no key material and
        // NOTE: are verified against the commit digest later, so the keyslot scan skips them.
        if (auto kind = peekExtensionKind(record->payload, position + recordPrefixSize);
            kind && *kind == signatureExtensionKind) {
            position += *size;
            continue;
        }
        auto slot = decodeKeyslot(record->payload, position + recordPrefixSize);
        if (!slot) {
            return tl::unexpected<Error>(slot.error());
        }
        // NOTE: count every keyslot record so a hostile archive cannot force unbounded KDF
        // work; decodeKeyslot already rejected over-cap params, so reaching unwrap is bounded.
        ++slotsSeen;
        if (slotsSeen > maxKeyslotsPerArchive) {
            return fail(ErrorKind::LimitExceeded, "too many keyslots", position);
        }
        if (keys.contains(slot->epoch)) {
            position += *size;
            continue;
        }
        bool unlocked = false;
        crypto::SecretBytes key;
        if (slot->kind == SlotKind::Password && unlock.hasPassword) {
            crypto::PasswordSlot pw;
            pw.epoch = slot->epoch;
            pw.salt = slot->salt;
            pw.opslimit = slot->opslimit;
            pw.memlimitBytes = slot->memlimitBytes;
            pw.nonce = slot->nonce;
            pw.wrapped = slot->wrapped;
            auto back = crypto::unwrapPasswordKey(pw, unlock.password.bytes());
            if (back) {
                key = std::move(*back);
                unlocked = true;
            } else if (back.error().kind != ErrorKind::Integrity) {
                return tl::unexpected<Error>(back.error());
            }
        } else if (slot->kind == SlotKind::Recipient) {
            for (const auto& recipient : unlock.recipients) {
                if (recipient.publicKey != slot->recipientPublic) {
                    continue;
                }
                crypto::RecipientSlot sealed;
                sealed.sealed = slot->sealed;
                auto back = crypto::unwrapRecipientKey(
                    sealed,
                    recipient.publicKey,
                    recipient.secretKey.bytes()
                );
                if (back) {
                    key = std::move(*back);
                    unlocked = true;
                    break;
                } else if (back.error().kind != ErrorKind::Integrity) {
                    return tl::unexpected<Error>(back.error());
                }
            }
        }
        if (unlocked) {
            keys.emplace(slot->epoch, std::move(key));
        }
        position += *size;
    }
    return keys;
}

}
