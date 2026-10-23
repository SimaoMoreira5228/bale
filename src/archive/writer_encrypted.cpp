#include "archive/chunk_pipeline.hpp"
#include "archive/encrypted.hpp"
#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "base/checked.hpp"
#include "base/endian.hpp"
#include "format/envelope.hpp"

#include <chrono>
#include <limits>
#include <random>

namespace bale::archive {

namespace {

std::array<std::byte, 16> randomId() {
    std::random_device source;
    std::array<std::byte, 16> id{};
    for (std::size_t index = 0; index < id.size(); index += 4) {
        storeLe(id.data() + index, static_cast<std::uint32_t>(source()));
    }
    id[6] = (id[6] & std::byte{0x0F}) | std::byte{0x40};
    id[8] = (id[8] & std::byte{0x3F}) | std::byte{0x80};
    return id;
}

std::span<const std::byte, 16> writerArchiveIdSpan(const std::array<std::byte, 16>& id) {
    return std::span<const std::byte, 16>(id.data(), 16);
}

}

Result<Writer::RecordSpan> Writer::writeKeyslots() {
    return fail(ErrorKind::Malformed, "unreachable keyslot writer");
}

Result<void> Writer::appendChunkEncrypted(ChunkSlot& slot) {
    if (!slot.indexPosition) {
        return {};
    }
    auto object = makeObjectId();
    if (!object) {
        return poison(object.error());
    }
    auto nonce = makeRecordNonce();
    if (!nonce) {
        return poison(nonce.error());
    }
    std::span<const std::byte> plain = slot.stored();
    auto aad = dataAad(writerArchiveIdSpan(archiveId_), *object, slot.codec, epoch_);
    auto sealed = crypto::seal(dataKey_.bytes(), *nonce, plain, aad);
    if (!sealed) {
        return poison(sealed.error());
    }
    if (sealed->size() != plain.size() + crypto::tagSize) {
        return poison(Error{.kind = ErrorKind::Malformed, .what = "seal size mismatch"});
    }

    std::vector<std::byte> head;
    head.reserve(encryptedDataHeaderSize);
    head.insert(head.end(), object->begin(), object->end());
    std::array<std::byte, 8> epochBytes{};
    storeLe(epochBytes.data(), epoch_);
    head.insert(head.end(), epochBytes.begin(), epochBytes.end());
    head.insert(head.end(), nonce->begin(), nonce->end());

    auto end = checkedAdd(plain.size(), crypto::tagSize);
    if (!end) {
        return poison(Error{.kind = ErrorKind::LimitExceeded, .what = "chunk too long to seal"});
    }
    auto span = writeRecord(RecordType::Data, head, *sealed, slot.codec, 0, encryptedRecordFlag);
    if (!span) {
        return tl::unexpected<Error>(span.error());
    }

    std::uint32_t position = *slot.indexPosition;
    index_[position].key.digest = *object;
    index_[position].key.length = slot.key.length;
    index_[position].recordOffset = span->offset;
    index_[position].recordLength = span->length;
    index_[position].codec = slot.codec;
    objectIds_[position] = *object;
    return {};
}

Result<Writer>
Writer::createEncrypted(File file, const WriterOptions& options, WriterSecrets&& secrets) {
    if (!options.experimentalEncryption) {
        return fail(ErrorKind::Malformed, "encrypted output requires --experimental-encryption");
    }
    if (auto valid = checkOptions(options); !valid) {
        return tl::unexpected<Error>(valid.error());
    }
    if (!secrets.hasPassword && secrets.recipientPublicKeys.empty()) {
        return fail(ErrorKind::Malformed, "encrypted archive needs a password or a recipient");
    }

    auto dataKey = crypto::makeKey();
    if (!dataKey) {
        return tl::unexpected<Error>(dataKey.error());
    }

    Writer writer(std::move(file), options);
    writer.encrypted_ = true;
    writer.epoch_ = 1;
    writer.dataKey_ = std::move(*dataKey);
    writer.hasPassword_ = secrets.hasPassword;
    if (secrets.hasPassword) {
        writer.password_ = std::move(secrets.password);
    }
    writer.recipientPubs_ = std::move(secrets.recipientPublicKeys);
    writer.kdf_ = secrets.kdf;
    writer.archiveId_ = options.archiveId ? *options.archiveId : randomId();
    if (auto started = writer.startPipeline(); !started) {
        return tl::unexpected<Error>(started.error());
    }

    Superblock superblock;
    superblock.archiveId = writer.archiveId_;
    if (options.creationTimeNanoseconds) {
        superblock.creationTimeNs = *options.creationTimeNanoseconds;
    } else {
        auto now = std::chrono::system_clock::now().time_since_epoch();
        superblock.creationTimeNs =
            std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    }
    superblock.requiredFeatures = encryptedRequiredFeature;
    if (options.parity.enabled) {
        superblock.requiredFeatures |= parityRequiredFeature;
    }
    if (auto written = writer.appendRaw(encodeSuperblock(superblock)); !written) {
        return tl::unexpected<Error>(written.error());
    }

    std::vector<Keyslot> slots;
    if (writer.hasPassword_) {
        auto wrapped = crypto::wrapPasswordKey(
            writer.dataKey_.bytes(),
            writer.password_.bytes(),
            writer.kdf_,
            writer.epoch_
        );
        if (!wrapped) {
            return tl::unexpected<Error>(wrapped.error());
        }
        Keyslot slot;
        slot.epoch = writer.epoch_;
        slot.kind = SlotKind::Password;
        slot.salt = wrapped->salt;
        slot.opslimit = wrapped->opslimit;
        slot.memlimitBytes = wrapped->memlimitBytes;
        slot.nonce = wrapped->nonce;
        slot.wrapped = std::move(wrapped->wrapped);
        slots.push_back(std::move(slot));
    }
    for (const auto& pub : writer.recipientPubs_) {
        auto wrapped = crypto::wrapRecipientKey(writer.dataKey_.bytes(), pub);
        if (!wrapped) {
            return tl::unexpected<Error>(wrapped.error());
        }
        Keyslot slot;
        slot.epoch = writer.epoch_;
        slot.kind = SlotKind::Recipient;
        slot.recipientPublic = pub;
        slot.sealed = std::move(wrapped->sealed);
        slots.push_back(std::move(slot));
    }
    for (const auto& slot : slots) {
        std::vector<std::byte> payload;
        if (auto encodedSlot = encodeKeyslot(slot, payload); !encodedSlot) {
            return tl::unexpected<Error>(encodedSlot.error());
        }
        auto span = writer.writeRecord(
            RecordType::Extension,
            payload,
            {},
            CodecId::Raw,
            0,
            encryptedRecordFlag
        );
        if (!span) {
            return tl::unexpected<Error>(span.error());
        }
    }
    return writer;
}

Result<Writer> Writer::appendEncrypted(
    File file,
    const WriterOptions& options,
    WriterSecrets&& secrets,
    ReaderUnlock&& unlock
) {
    if (!options.experimentalEncryption) {
        return fail(ErrorKind::Malformed, "encrypted output requires --experimental-encryption");
    }
    if (auto valid = checkOptions(options); !valid) {
        return tl::unexpected<Error>(valid.error());
    }
    if (!secrets.hasPassword && secrets.recipientPublicKeys.empty()) {
        return fail(ErrorKind::Malformed, "encrypted archive needs a password or a recipient");
    }

    auto readFile = file.duplicate();
    if (!readFile) {
        return tl::unexpected<Error>(readFile.error());
    }
    auto reader = Reader::openEncrypted(std::move(*readFile), ReaderOptions{}, std::move(unlock));
    if (!reader) {
        return tl::unexpected<Error>(reader.error());
    }
    if (reader->commit().generation == std::numeric_limits<std::uint64_t>::max()) {
        return fail(ErrorKind::LimitExceeded, "archive generation limit exceeded");
    }
    if (options.parity.enabled &&
        (reader->superblock().requiredFeatures & parityRequiredFeature) == 0) {
        return fail(
            ErrorKind::Malformed,
            "archive superblock was created without parity; recreate with --parity to enable it"
        );
    }

    auto dataKey = crypto::makeKey();
    if (!dataKey) {
        return tl::unexpected<Error>(dataKey.error());
    }

    Writer writer(std::move(file), options);
    writer.encrypted_ = true;
    writer.dataKey_ = std::move(*dataKey);
    writer.hasPassword_ = secrets.hasPassword;
    if (secrets.hasPassword) {
        writer.password_ = std::move(secrets.password);
    }
    writer.recipientPubs_ = std::move(secrets.recipientPublicKeys);
    writer.kdf_ = secrets.kdf;
    writer.archiveId_ = reader->superblock().archiveId;
    if (auto started = writer.startPipeline(); !started) {
        return tl::unexpected<Error>(started.error());
    }

    std::uint64_t position = reader->footerOffset() + footerSize;
    if (auto truncated = writer.file_.truncate(position); !truncated) {
        return tl::unexpected<Error>(truncated.error());
    }
    writer.position_ = position;
    writer.sequence_ = reader->sequenceCount();
    writer.generationStart_ = position;
    writer.generation_ = reader->commit().generation + 1;
    writer.previousCommit_ = reader->commitDigest();
    writer.previousFooterOffset_ = reader->footerOffset();
    writer.epoch_ = writer.generation_;

    std::vector<Keyslot> slots;
    if (writer.hasPassword_) {
        auto wrapped = crypto::wrapPasswordKey(
            writer.dataKey_.bytes(),
            writer.password_.bytes(),
            writer.kdf_,
            writer.epoch_
        );
        if (!wrapped) {
            return tl::unexpected<Error>(wrapped.error());
        }
        Keyslot slot;
        slot.epoch = writer.epoch_;
        slot.kind = SlotKind::Password;
        slot.salt = wrapped->salt;
        slot.opslimit = wrapped->opslimit;
        slot.memlimitBytes = wrapped->memlimitBytes;
        slot.nonce = wrapped->nonce;
        slot.wrapped = std::move(wrapped->wrapped);
        slots.push_back(std::move(slot));
    }
    for (const auto& pub : writer.recipientPubs_) {
        auto wrapped = crypto::wrapRecipientKey(writer.dataKey_.bytes(), pub);
        if (!wrapped) {
            return tl::unexpected<Error>(wrapped.error());
        }
        Keyslot slot;
        slot.epoch = writer.epoch_;
        slot.kind = SlotKind::Recipient;
        slot.recipientPublic = pub;
        slot.sealed = std::move(wrapped->sealed);
        slots.push_back(std::move(slot));
    }
    for (const auto& slot : slots) {
        std::vector<std::byte> payload;
        if (auto encodedSlot = encodeKeyslot(slot, payload); !encodedSlot) {
            return tl::unexpected<Error>(encodedSlot.error());
        }
        auto span = writer.writeRecord(
            RecordType::Extension,
            payload,
            {},
            CodecId::Raw,
            0,
            encryptedRecordFlag
        );
        if (!span) {
            return tl::unexpected<Error>(span.error());
        }
    }
    return writer;
}

}
