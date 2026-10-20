#pragma once

#include "archive/parity.hpp"
#include "archive/parity_scan.hpp"
#include "base/error.hpp"
#include "crypto/secrets.hpp"
#include "format/envelope.hpp"
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

struct RepairKeys {
    std::map<std::uint64_t, crypto::SecretBytes> byEpoch;
    std::array<std::byte, 16> archiveId{};
};

struct GenerationRepair {
    std::uint64_t generation = 0;
    bool attempted = false;
    bool repaired = false;
    std::uint64_t repairedBytes = 0;
    std::uint64_t repairedRecords = 0;
    std::string note;
};

struct RepairOutcome {
    bool changed = false;
    std::vector<GenerationRepair> generations;
};

[[nodiscard]] Result<RepairOutcome> repairParityGenerations(
    File& file,
    std::uint64_t fileSize,
    const Superblock& superblock,
    const Limits& limits,
    const RepairKeys* keys
);

}
