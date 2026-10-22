#pragma once

#include "archive/parity.hpp"
#include "base/error.hpp"
#include "format/record.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bale::archive {

struct ScannedRecord {
    RecordType type = RecordType::Data;
    std::uint16_t flags = 0;
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    std::uint64_t sequence = 0;
    CodecId codec = CodecId::Raw;
    std::uint32_t extensionKind = 0;
    bool hasExtensionKind = false;
};

struct GenerationScan {
    std::vector<ScannedRecord> records;
    bool truncated = false;
};

[[nodiscard]] Result<GenerationScan>
scanGeneration(File& file, std::uint64_t start, std::uint64_t end, std::uint64_t maxPayload);

}
