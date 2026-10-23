#include "archive/chunk.hpp"

#include <algorithm>

namespace bale::archive {

ChunkKey chunkKeyOf(std::span<const std::byte> chunk) {
    return ChunkKey{
        .algorithm = HashAlgorithm::Blake3,
        .digest = Blake3::of(HashDomain::Chunk, chunk),
        .length = chunk.size(),
    };
}

Result<void> writeChunkKey(TlvWriter& writer, const ChunkKey& key) {
    auto algorithm = writer.unsignedValue(
        keyAlgorithmField,
        Criticality::Critical,
        static_cast<std::uint64_t>(key.algorithm)
    );
    if (!algorithm) {
        return algorithm;
    }

    auto digest = writer.bytes(keyDigestField, Criticality::Critical, key.digest);
    if (!digest) {
        return digest;
    }
    return writer.unsignedValue(keyLengthField, Criticality::Critical, key.length);
}

Result<bool> ChunkKeyFields::accept(const TlvField& field) {
    if (field.number < keyAlgorithmField || field.number > keyLengthField) {
        return false;
    }

    auto critical = requireCriticality(field, Criticality::Critical);
    if (!critical) {
        return tl::unexpected<Error>(critical.error());
    }

    if (field.number == keyDigestField) {
        if (field.value.size() != key_.digest.size()) {
            return fail(ErrorKind::Malformed, "chunk digest is not 32 bytes", field.offset);
        }
        std::ranges::copy(field.value, key_.digest.begin());
        hasDigest_ = true;
        return true;
    }

    auto value = decodeTlvUnsigned(field);
    if (!value) {
        return tl::unexpected<Error>(value.error());
    }

    if (field.number == keyAlgorithmField) {
        if (*value != static_cast<std::uint64_t>(HashAlgorithm::Blake3) &&
            *value != static_cast<std::uint64_t>(HashAlgorithm::EncryptedObject)) {
            return fail(ErrorKind::Unsupported, "unknown chunk hash algorithm", field.offset);
        }
        key_.algorithm = static_cast<HashAlgorithm>(*value);
        hasAlgorithm_ = true;
        return true;
    }

    if (*value == 0) {
        return fail(ErrorKind::Malformed, "empty chunk", field.offset);
    }
    if (*value > maxChunkSize) {
        return fail(
            ErrorKind::LimitExceeded,
            "chunk length exceeds the format maximum",
            field.offset
        );
    }
    key_.length = *value;
    hasLength_ = true;
    return true;
}

Result<ChunkKey> ChunkKeyFields::finish(std::uint64_t offset) const {
    if (!hasAlgorithm_ || !hasDigest_ || !hasLength_) {
        return fail(ErrorKind::Malformed, "chunk key is missing a field", offset);
    }
    return key_;
}

Result<ChunkKey> decodeChunkKey(std::span<const std::byte> data, std::uint64_t offset) {
    TlvReader reader(data, offset);
    ChunkKeyFields fields;
    TlvField field;
    while (true) {
        auto more = reader.next(field);
        if (!more) {
            return tl::unexpected<Error>(more.error());
        }
        if (!*more) {
            return fields.finish(offset);
        }

        auto accepted = fields.accept(field);
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
}

Result<void> encodeDataDescriptor(const ChunkKey& key, std::vector<std::byte>& out) {
    out.clear();
    out.push_back(std::byte{0});

    TlvWriter writer(out);
    auto written = writeChunkKey(writer, key);
    if (!written) {
        return written;
    }

    std::size_t size = out.size() - 1;
    if (size >= 0x80) {
        return fail(ErrorKind::Malformed, "data descriptor too large");
    }
    out[0] = static_cast<std::byte>(size);
    return {};
}

Result<DataPayload> decodeDataPayload(std::span<const std::byte> payload, std::uint64_t offset) {
    auto size = decodeLeb128(payload, offset);
    if (!size) {
        return tl::unexpected<Error>(size.error());
    }
    if (size->value > maxDataDescriptorSize) {
        return fail(ErrorKind::LimitExceeded, "data descriptor too large", offset);
    }
    if (size->value > payload.size() - size->size) {
        return fail(ErrorKind::Truncated, "data descriptor extends past payload", offset);
    }

    auto descriptorSize = static_cast<std::size_t>(size->value);
    auto key = decodeChunkKey(payload.subspan(size->size, descriptorSize), offset + size->size);
    if (!key) {
        return tl::unexpected<Error>(key.error());
    }
    if (key->algorithm != HashAlgorithm::Blake3) {
        return fail(ErrorKind::Unsupported, "unknown chunk hash algorithm", offset);
    }

    std::size_t prefix = size->size + descriptorSize;
    return DataPayload{
        .key = *key,
        .descriptorSize = prefix,
        .encoded = payload.subspan(prefix),
    };
}

}
