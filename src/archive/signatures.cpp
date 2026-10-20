#include "archive/signatures.hpp"

#include "base/endian.hpp"
#include "format/tlv.hpp"

#include <algorithm>
#include <string_view>

namespace bale::archive {

namespace {

constexpr std::uint32_t sigKindField = 1;
constexpr std::uint32_t sigVersionField = 2;
constexpr std::uint32_t sigEpochField = 3;
constexpr std::uint32_t sigSignerField = 4;
constexpr std::uint32_t sigSignatureField = 5;

constexpr std::string_view signatureDomain = "bale-sig-v1/commit";

void appendU64Le(std::vector<std::byte>& out, std::uint64_t value) {
    std::array<std::byte, 8> encoded{};
    storeLe(encoded.data(), value);
    out.insert(out.end(), encoded.begin(), encoded.end());
}

}

Result<void> encodeSignature(const Signature& signature, std::vector<std::byte>& out) {
    out.clear();
    TlvWriter writer(out);
    auto kind = writer.unsignedValue(sigKindField, Criticality::Critical, signatureExtensionKind);
    if (!kind) {
        return kind;
    }
    auto version = writer.unsignedValue(sigVersionField, Criticality::Critical, signatureVersion);
    if (!version) {
        return version;
    }
    auto epoch = writer.unsignedValue(sigEpochField, Criticality::Critical, signature.epoch);
    if (!epoch) {
        return epoch;
    }
    auto signer = writer.bytes(sigSignerField, Criticality::Critical, signature.signer);
    if (!signer) {
        return signer;
    }
    return writer.bytes(sigSignatureField, Criticality::Critical, signature.signature);
}

Result<Signature> decodeSignature(std::span<const std::byte> payload, std::uint64_t offset) {
    Signature signature;
    bool hasKind = false;
    bool hasVersion = false;
    bool hasEpoch = false;
    bool hasSigner = false;
    bool hasSignature = false;

    TlvReader reader(payload, offset);
    TlvField field;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return std::unexpected(more.error());
        }
        if (!*more) {
            break;
        }
        if (field.number > sigSignatureField) {
            auto skipped = skipUnknownField(field);
            if (!skipped) {
                return std::unexpected(skipped.error());
            }
            continue;
        }
        bool known = field.number == sigKindField || field.number == sigVersionField ||
            field.number == sigEpochField || field.number == sigSignerField ||
            field.number == sigSignatureField;
        if (!known) {
            auto skipped = skipUnknownField(field);
            if (!skipped) {
                return std::unexpected(skipped.error());
            }
            continue;
        }
        auto critical = requireCriticality(field, Criticality::Critical);
        if (!critical) {
            return std::unexpected(critical.error());
        }
        switch (field.number) {
        case sigKindField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return std::unexpected(value.error());
            }
            if (*value != signatureExtensionKind) {
                return fail(ErrorKind::Unsupported, "unknown extension kind", field.offset);
            }
            if (hasKind) {
                return fail(ErrorKind::Malformed, "duplicate signature kind", field.offset);
            }
            hasKind = true;
            break;
        }
        case sigVersionField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return std::unexpected(value.error());
            }
            if (*value != signatureVersion) {
                return fail(ErrorKind::Unsupported, "unsupported signature version", field.offset);
            }
            if (hasVersion) {
                return fail(ErrorKind::Malformed, "duplicate signature version", field.offset);
            }
            hasVersion = true;
            break;
        }
        case sigEpochField: {
            auto value = decodeTlvUnsigned(field);
            if (!value) {
                return std::unexpected(value.error());
            }
            if (hasEpoch) {
                return fail(ErrorKind::Malformed, "duplicate signature epoch", field.offset);
            }
            signature.epoch = *value;
            hasEpoch = true;
            break;
        }
        case sigSignerField:
            if (field.value.size() != signerIdSize) {
                return fail(ErrorKind::Malformed, "signer id has a bad size", field.offset);
            }
            if (hasSigner) {
                return fail(ErrorKind::Malformed, "duplicate signer id", field.offset);
            }
            std::ranges::copy(field.value, signature.signer.begin());
            hasSigner = true;
            break;
        case sigSignatureField:
            if (field.value.size() != signatureSize) {
                return fail(ErrorKind::Malformed, "signature has a bad size", field.offset);
            }
            if (hasSignature) {
                return fail(ErrorKind::Malformed, "duplicate signature", field.offset);
            }
            std::ranges::copy(field.value, signature.signature.begin());
            hasSignature = true;
            break;
        default:
            return fail(ErrorKind::Malformed, "unreachable signature field", field.offset);
        }
    }

    if (!hasKind || !hasVersion || !hasEpoch || !hasSigner || !hasSignature) {
        return fail(ErrorKind::Malformed, "signature missing a required field", offset);
    }
    return signature;
}

Result<std::uint32_t> peekExtensionKind(std::span<const std::byte> payload, std::uint64_t offset) {
    TlvReader reader(payload, offset);
    TlvField field;
    auto more = reader.next(field);
    if (!more) {
        return std::unexpected(more.error());
    }
    if (!*more) {
        return fail(ErrorKind::Malformed, "extension payload is empty", offset);
    }
    if (field.number != sigKindField) {
        return fail(ErrorKind::Malformed, "extension kind is not the first field", field.offset);
    }
    auto critical = requireCriticality(field, Criticality::Critical);
    if (!critical) {
        return std::unexpected(critical.error());
    }
    auto value = decodeTlvUnsigned(field);
    if (!value) {
        return std::unexpected(value.error());
    }
    if (*value > maxTlvFieldNumber) {
        return fail(ErrorKind::Malformed, "extension kind out of range", field.offset);
    }
    return static_cast<std::uint32_t>(*value);
}

std::vector<std::byte> signatureMessage(
    std::span<const std::byte, 16> archiveId,
    std::uint64_t generation,
    std::uint64_t epoch,
    std::span<const std::byte, 32> commitDigest
) {
    std::vector<std::byte> out;
    out.reserve(signatureDomain.size() + 16 + 8 + 8 + 32);
    out.insert(
        out.end(),
        reinterpret_cast<const std::byte*>(signatureDomain.data()),
        reinterpret_cast<const std::byte*>(signatureDomain.data() + signatureDomain.size())
    );
    out.insert(out.end(), archiveId.begin(), archiveId.end());
    appendU64Le(out, generation);
    appendU64Le(out, epoch);
    out.insert(out.end(), commitDigest.begin(), commitDigest.end());
    return out;
}

Result<Signature> makeSignature(
    std::span<const std::byte> seed,
    std::span<const std::byte, 16> archiveId,
    std::uint64_t generation,
    std::uint64_t epoch,
    std::span<const std::byte, 32> commitDigest
) {
    if (generation == 0) {
        return fail(ErrorKind::Malformed, "cannot sign generation zero");
    }
    auto publicKey = crypto::signPublicKeyOf(seed);
    if (!publicKey) {
        return std::unexpected(publicKey.error());
    }
    auto message = signatureMessage(archiveId, generation, epoch, commitDigest);
    auto signature = crypto::signDetached(message, seed);
    if (!signature) {
        return std::unexpected(signature.error());
    }
    Signature out;
    out.epoch = epoch;
    out.signer = *publicKey;
    out.signature = *signature;
    return out;
}

Result<void> checkSignature(
    const Signature& signature,
    std::span<const std::byte> publicKey,
    std::span<const std::byte, 16> archiveId,
    std::uint64_t generation,
    std::uint64_t epoch,
    std::span<const std::byte, 32> commitDigest
) {
    if (publicKey.size() != signerIdSize) {
        return fail(ErrorKind::Malformed, "verification key must hold 32 bytes");
    }
    if (!std::ranges::equal(signature.signer, publicKey)) {
        return fail(ErrorKind::Integrity, "signature is from another key", 0);
    }
    if (signature.epoch != epoch) {
        return fail(ErrorKind::Integrity, "signature epoch differs from the commit", 0);
    }
    auto message = signatureMessage(archiveId, generation, epoch, commitDigest);
    return crypto::verifyDetached(signature.signature, message, publicKey);
}

}
