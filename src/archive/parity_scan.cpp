#include "archive/parity_scan.hpp"

#include "archive/signatures.hpp"
#include "base/checked.hpp"

#include <array>

namespace bale::archive {

Result<GenerationScan>
scanGeneration(File& file, std::uint64_t start, std::uint64_t end, std::uint64_t maxPayload) {
    GenerationScan scan;
    if (start > end) {
        return fail(ErrorKind::Malformed, "generation range runs backward", start);
    }
    auto capacity = checkedAdd((end - start) / recordFramingSize, std::uint64_t{1});
    if (!capacity) {
        return fail(ErrorKind::LimitExceeded, "generation scan range overflows");
    }
    if (*capacity > std::uint64_t{16} << 20) {
        return fail(ErrorKind::LimitExceeded, "generation holds too many records", start);
    }

    RecordLimits limits{
        .maxPayloadLength = maxPayload,
        .maxDecodedLength = maxPayload,
    };
    std::array<std::byte, recordPrefixSize> prefix{};
    std::vector<std::byte> recordBytes;
    std::uint64_t position = start;
    while (position < end) {
        if (end - position < recordFramingSize) {
            scan.truncated = true;
            break;
        }
        if (scan.records.size() >= *capacity) {
            return fail(ErrorKind::LimitExceeded, "generation holds too many records", position);
        }
        if (auto read = file.readExactAt(position, prefix); !read) {
            if (read.error().kind == ErrorKind::Truncated) {
                scan.truncated = true;
                break;
            }
            return std::unexpected(read.error());
        }
        auto header = decodeRecordPrefix(prefix, limits, position);
        if (!header) {
            scan.truncated = true;
            break;
        }
        auto size = recordSize(header->payloadLength);
        if (!size || !fitsWithin(position, *size, end)) {
            scan.truncated = true;
            break;
        }
        ScannedRecord record{
            .type = header->type,
            .flags = header->flags,
            .offset = position,
            .length = *size,
            .sequence = header->sequence,
            .codec = header->codec,
        };
        if (header->type == RecordType::Extension) {
            recordBytes.resize(static_cast<std::size_t>(*size));
            if (auto read = file.readExactAt(position, recordBytes); !read) {
                if (read.error().kind == ErrorKind::Truncated) {
                    scan.truncated = true;
                    break;
                }
                return std::unexpected(read.error());
            }
            auto decoded = decodeRecord(recordBytes, limits, position);
            if (!decoded) {
                scan.truncated = true;
                break;
            }
            auto kind = peekExtensionKind(decoded->payload, position + recordPrefixSize);
            if (!kind) {
                scan.truncated = true;
                break;
            }
            record.extensionKind = *kind;
            record.hasExtensionKind = true;
        }
        scan.records.push_back(record);
        position += *size;
    }
    return scan;
}

}
