#include "archive/writer.hpp"

#include "archive/encrypted.hpp"
#include "archive/parity_scan.hpp"
#include "archive/signatures.hpp"
#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "format/envelope.hpp"
#include "parity/reed_solomon.hpp"

#include <random>

namespace bale::archive {

namespace {

std::uint64_t randomGroupId() {
    std::random_device source;
    std::uint64_t group = 0;
    while (group == 0) {
        group = (static_cast<std::uint64_t>(source()) << 32) | source();
    }
    return group;
}

struct PayloadRange {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
};

Result<PayloadRange> payloadOf(const ScannedRecord& record) {
    if (record.length < recordFramingSize) {
        return fail(ErrorKind::Malformed, "record shorter than framing", record.offset);
    }
    auto payloadOffset = checkedAdd(record.offset, static_cast<std::uint64_t>(recordPrefixSize));
    if (!payloadOffset) {
        return fail(ErrorKind::LimitExceeded, "record payload offset overflows", record.offset);
    }
    return PayloadRange{
        .offset = *payloadOffset,
        .length = record.length - recordFramingSize,
    };
}

Result<void> copyStreamRange(
    File& file,
    std::span<const PayloadRange> segments,
    std::uint64_t streamOffset,
    std::span<std::byte> out
) {
    std::uint64_t position = 0;
    std::size_t filled = 0;
    for (const auto& segment : segments) {
        if (filled == out.size()) {
            break;
        }
        auto segmentEnd = checkedAdd(position, segment.length);
        if (!segmentEnd) {
            return fail(ErrorKind::LimitExceeded, "parity stream range overflows");
        }
        if (streamOffset >= *segmentEnd) {
            position = *segmentEnd;
            continue;
        }
        std::uint64_t skip = streamOffset > position ? streamOffset - position : 0;
        std::uint64_t available = segment.length - skip;
        std::size_t take = static_cast<std::size_t>(
            std::min<std::uint64_t>(available, static_cast<std::uint64_t>(out.size() - filled))
        );
        auto rangeStart = checkedAdd(segment.offset, skip);
        if (!rangeStart) {
            return fail(ErrorKind::LimitExceeded, "parity stream range overflows");
        }
        auto read = file.readExactAt(*rangeStart, out.subspan(filled, take));
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        filled += take;
        position = *segmentEnd;
    }
    for (; filled < out.size(); ++filled) {
        out[filled] = std::byte{0};
    }
    return {};
}

}

Result<ParityDescriptor> Writer::emitParity(
    const RecordSpan& manifest,
    const RecordSpan& index,
    const RecordSpan& commitRecord
) {
    auto failed = [this](const Error& error) {
        return tl::unexpected<Error>(poison(error).error());
    };
    if (auto flushed = flushOutput(); !flushed) {
        return failed(flushed.error());
    }

    auto scan = scanGeneration(
        file_,
        generationStart_,
        position_,
        std::max(maxEncryptedPayloadBytes, std::uint64_t{256} << 20)
    );
    if (!scan) {
        return failed(scan.error());
    }
    if (scan->truncated) {
        return failed(
            Error{
                .kind = ErrorKind::Malformed,
                .what = "generation changed during parity emission",
            }
        );
    }

    std::vector<PayloadRange> dataPayloads;
    std::vector<PayloadRange> keyslotPayloads;
    std::uint64_t previousSequence = 0;
    bool hasSequence = false;
    for (const auto& record : scan->records) {
        if (record.type == RecordType::Parity) {
            return failed(
                Error{
                    .kind = ErrorKind::Malformed,
                    .what = "parity records already present in this generation",
                    .offset = record.offset,
                }
            );
        }
        if (record.type == RecordType::Data) {
            if (hasSequence && record.sequence <= previousSequence) {
                return failed(
                    Error{
                        .kind = ErrorKind::Malformed,
                        .what = "data records out of sequence order",
                        .offset = record.offset,
                    }
                );
            }
            previousSequence = record.sequence;
            hasSequence = true;
            auto payload = payloadOf(record);
            if (!payload) {
                return failed(payload.error());
            }
            dataPayloads.push_back(*payload);
        }
        if (record.type == RecordType::Extension && record.hasExtensionKind &&
            record.extensionKind == keyslotExtensionKind) {
            auto payload = payloadOf(record);
            if (!payload) {
                return failed(payload.error());
            }
            keyslotPayloads.push_back(*payload);
        }
    }

    auto manifestPayload = payloadOf(
        ScannedRecord{
            .type = RecordType::Manifest,
            .offset = manifest.offset,
            .length = manifest.length,
        }
    );
    if (!manifestPayload) {
        return failed(manifestPayload.error());
    }
    auto indexPayload = payloadOf(
        ScannedRecord{
            .type = RecordType::Index,
            .offset = index.offset,
            .length = index.length,
        }
    );
    if (!indexPayload) {
        return failed(indexPayload.error());
    }
    auto commitPayload = payloadOf(
        ScannedRecord{
            .type = RecordType::Commit,
            .offset = commitRecord.offset,
            .length = commitRecord.length,
        }
    );
    if (!commitPayload) {
        return failed(commitPayload.error());
    }

    std::vector<PayloadRange> segments;
    segments.reserve(dataPayloads.size() + keyslotPayloads.size() + static_cast<std::size_t>(3));
    segments.insert(segments.end(), dataPayloads.begin(), dataPayloads.end());
    segments.push_back(*indexPayload);
    segments.push_back(*manifestPayload);
    segments.push_back(*commitPayload);
    segments.insert(segments.end(), keyslotPayloads.begin(), keyslotPayloads.end());

    std::uint64_t streamLength = 0;
    for (const auto& segment : segments) {
        auto next = checkedAdd(streamLength, segment.length);
        if (!next) {
            return failed(
                Error{
                    .kind = ErrorKind::LimitExceeded,
                    .what = "parity stream length overflows",
                }
            );
        }
        streamLength = *next;
    }

    auto descriptor = makeParityDescriptor(options_.parity, streamLength, randomGroupId());
    if (!descriptor) {
        return failed(descriptor.error());
    }

    auto coder = parity::ReedSolomon::make(descriptor->dataShards, descriptor->parityShards);
    if (!coder) {
        return failed(coder.error());
    }
    auto scratchSize =
        parity::ReedSolomon::scratchBytes(descriptor->dataShards, descriptor->parityShards);
    if (!scratchSize) {
        return failed(scratchSize.error());
    }
    std::vector<std::byte> scratch(*scratchSize);
    std::vector<std::vector<std::byte>> dataShards(
        descriptor->dataShards,
        std::vector<std::byte>(descriptor->shardBytes)
    );
    std::vector<std::vector<std::byte>> parityShards(
        descriptor->parityShards,
        std::vector<std::byte>(descriptor->shardBytes)
    );
    std::vector<std::span<const std::byte>> dataViews(descriptor->dataShards);
    std::vector<std::span<std::byte>> parityViews(descriptor->parityShards);
    for (std::uint32_t shard = 0; shard < descriptor->dataShards; ++shard) {
        dataViews[shard] = dataShards[shard];
    }
    for (std::uint32_t shard = 0; shard < descriptor->parityShards; ++shard) {
        parityViews[shard] = parityShards[shard];
    }

    std::uint64_t stripeBytes =
        static_cast<std::uint64_t>(descriptor->dataShards) * descriptor->shardBytes;
    std::vector<std::byte> encoded;
    for (std::uint64_t stripe = 0; stripe < descriptor->stripeCount; ++stripe) {
        auto stripeStart = checkedMul(stripe, stripeBytes);
        if (!stripeStart) {
            return failed(
                Error{
                    .kind = ErrorKind::LimitExceeded,
                    .what = "parity stripe offset overflows",
                }
            );
        }
        ParityHeader header;
        header.groupId = descriptor->groupId;
        header.generation = generation_;
        header.stripeIndex = stripe;
        header.dataShards = descriptor->dataShards;
        header.parityShards = descriptor->parityShards;
        header.shardBytes = descriptor->shardBytes;
        header.stripeCount = descriptor->stripeCount;
        header.streamLength = streamLength;
        header.crc.assign(descriptor->dataShards + descriptor->parityShards, 0);
        for (std::uint32_t shard = 0; shard < descriptor->dataShards; ++shard) {
            auto shardStart = checkedAdd(
                *stripeStart,
                static_cast<std::uint64_t>(shard) * descriptor->shardBytes
            );
            if (!shardStart) {
                return failed(
                    Error{
                        .kind = ErrorKind::LimitExceeded,
                        .what = "parity shard offset overflows",
                    }
                );
            }
            if (auto copied = copyStreamRange(file_, segments, *shardStart, dataShards[shard]);
                !copied) {
                return failed(copied.error());
            }
            header.crc[shard] = Crc32c::of(dataShards[shard]);
        }
        if (auto encodedShards = coder->encode(dataViews, parityViews); !encodedShards) {
            return failed(encodedShards.error());
        }
        for (std::uint32_t shard = 0; shard < descriptor->parityShards; ++shard) {
            header.crc[descriptor->dataShards + shard] = Crc32c::of(parityShards[shard]);
        }
        for (std::uint32_t shard = 0; shard < descriptor->parityShards; ++shard) {
            header.shardIndex = descriptor->dataShards + shard;
            if (auto packed = encodeParityRecord(header, parityShards[shard], encoded); !packed) {
                return failed(packed.error());
            }
            std::uint16_t flags = parityRecordFlag;
            if (encrypted_) {
                flags |= encryptedRecordFlag;
            }
            if (auto written = writeRecord(RecordType::Parity, encoded, {}, CodecId::Raw, 0, flags);
                !written) {
                return tl::unexpected<Error>(written.error());
            }
        }
    }
    return *descriptor;
}

}
