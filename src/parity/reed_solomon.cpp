#include "parity/reed_solomon.hpp"

#include "base/checked.hpp"

#include <array>
#include <cstddef>

namespace bale::parity {

namespace {

constexpr std::uint8_t gfMultiplySlow(std::uint8_t a, std::uint8_t b) {
    std::uint32_t product = 0;
    std::uint32_t factor = a;
    std::uint32_t multiplier = b;
    while (multiplier != 0) {
        if ((multiplier & 1) != 0) {
            product ^= factor;
        }
        factor <<= 1;
        if ((factor & 0x100) != 0) {
            factor ^= gfPrimitivePolynomial;
        }
        multiplier >>= 1;
    }
    return static_cast<std::uint8_t>(product & 0xFF);
}

constexpr std::array<std::uint8_t, 512> makeExpTable() {
    std::array<std::uint8_t, 512> table{};
    table[0] = 1;
    for (std::size_t index = 1; index < table.size(); ++index) {
        table[index] = gfMultiplySlow(table[index - 1], 2);
    }
    return table;
}

constexpr std::array<std::uint8_t, 256> makeLogTable(const std::array<std::uint8_t, 512>& exp) {
    std::array<std::uint8_t, 256> table{};
    for (std::uint32_t index = 0; index < 255; ++index) {
        table[exp[index]] = static_cast<std::uint8_t>(index);
    }
    return table;
}

constexpr std::array<std::uint8_t, 512> expTable = makeExpTable();
constexpr std::array<std::uint8_t, 256> logTable = makeLogTable(expTable);

[[nodiscard]] std::uint8_t cauchyCoefficient(std::uint32_t parityRow, std::uint32_t dataColumn) {
    // NOTE: make() keeps the x set {255..256-m} disjoint from the y set
    // NOTE: {0..k-1}, so x ^ y is never zero and the inverse always exists.
    const auto x = static_cast<std::uint8_t>(255 - parityRow);
    const auto y = static_cast<std::uint8_t>(dataColumn);
    const auto difference = static_cast<std::uint8_t>(x ^ y);
    return expTable[255 - logTable[difference]];
}

// NOTE: matrix lives in caller scratch as [M | Inv], each half k*k bytes.
[[nodiscard]] Result<void> invertMatrix(std::span<std::byte> scratch, std::uint32_t order) {
    const std::size_t side = order;
    const std::size_t half = side * side;
    auto at = [&](std::size_t row, std::size_t col) -> std::uint8_t {
        return std::to_integer<std::uint8_t>(scratch[row * side + col]);
    };
    auto set = [&](std::size_t row, std::size_t col, std::uint8_t value) {
        scratch[row * side + col] = static_cast<std::byte>(value);
    };
    auto atInv = [&](std::size_t row, std::size_t col) -> std::uint8_t {
        return std::to_integer<std::uint8_t>(scratch[half + row * side + col]);
    };
    auto setInv = [&](std::size_t row, std::size_t col, std::uint8_t value) {
        scratch[half + row * side + col] = static_cast<std::byte>(value);
    };

    for (std::uint32_t column = 0; column < order; ++column) {
        std::uint32_t pivot = order;
        for (std::uint32_t row = column; row < order; ++row) {
            if (at(row, column) != 0) {
                pivot = row;
                break;
            }
        }
        if (pivot == order) {
            return fail(ErrorKind::Integrity, "parity decode matrix is singular");
        }
        if (pivot != column) {
            for (std::uint32_t scan = 0; scan < order; ++scan) {
                const std::uint8_t left = at(column, scan);
                set(column, scan, at(pivot, scan));
                set(pivot, scan, left);
                const std::uint8_t right = atInv(column, scan);
                setInv(column, scan, atInv(pivot, scan));
                setInv(pivot, scan, right);
            }
        }
        auto inverted = gf::inverse(at(column, column));
        if (!inverted) {
            return std::unexpected(inverted.error());
        }
        const std::uint8_t scale = *inverted;
        for (std::uint32_t scan = 0; scan < order; ++scan) {
            set(column, scan, gf::multiply(at(column, scan), scale));
            setInv(column, scan, gf::multiply(atInv(column, scan), scale));
        }
        for (std::uint32_t row = 0; row < order; ++row) {
            if (row == column) {
                continue;
            }
            const std::uint8_t factor = at(row, column);
            if (factor == 0) {
                continue;
            }
            for (std::uint32_t scan = 0; scan < order; ++scan) {
                set(row, scan, at(row, scan) ^ gf::multiply(factor, at(column, scan)));
                setInv(row, scan, atInv(row, scan) ^ gf::multiply(factor, atInv(column, scan)));
            }
        }
    }
    return {};
}

[[nodiscard]] Result<std::size_t> shardLength(std::span<const std::span<const std::byte>> shards) {
    if (shards.empty()) {
        return fail(ErrorKind::Malformed, "parity needs at least one shard to size");
    }
    const std::size_t length = shards[0].size();
    if (length == 0) {
        return fail(ErrorKind::Malformed, "parity shards must not be empty");
    }
    if (length > maxShardBytes) {
        return fail(ErrorKind::LimitExceeded, "parity shard exceeds the size cap");
    }
    for (const auto& shard : shards) {
        if (shard.size() != length) {
            return fail(ErrorKind::Malformed, "parity shards must share one length");
        }
    }
    return length;
}

}

namespace gf {

std::uint8_t multiply(std::uint8_t a, std::uint8_t b) {
    if (a == 0 || b == 0) {
        return 0;
    }
    return expTable[logTable[a] + logTable[b]];
}

Result<std::uint8_t> inverse(std::uint8_t value) {
    if (value == 0) {
        return fail(ErrorKind::Malformed, "zero has no field inverse");
    }
    return expTable[255 - logTable[value]];
}

std::uint8_t exp(int exponent) {
    int reduced = exponent % 255;
    if (reduced < 0) {
        reduced += 255;
    }
    return expTable[static_cast<std::size_t>(reduced)];
}

Result<std::uint8_t> log(std::uint8_t value) {
    if (value == 0) {
        return fail(ErrorKind::Malformed, "zero has no field logarithm");
    }
    return logTable[value];
}

}

Result<ReedSolomon> ReedSolomon::make(std::uint32_t dataShards, std::uint32_t parityShards) {
    if (dataShards == 0 || parityShards == 0) {
        return fail(ErrorKind::Malformed, "parity needs at least one data and one parity shard");
    }
    auto total = checkedAdd(dataShards, parityShards);
    if (!total || *total > maxTotalShards) {
        return fail(ErrorKind::LimitExceeded, "shard count exceeds the field order");
    }
    return ReedSolomon(dataShards, parityShards);
}

Result<std::size_t>
ReedSolomon::scratchBytes(std::uint32_t dataShards, std::uint32_t parityShards) {
    if (dataShards == 0 || parityShards == 0) {
        return fail(ErrorKind::Malformed, "parity needs at least one data and one parity shard");
    }
    auto total = checkedAdd(dataShards, parityShards);
    if (!total || *total > maxTotalShards) {
        return fail(ErrorKind::LimitExceeded, "shard count exceeds the field order");
    }
    auto square =
        checkedMul(static_cast<std::size_t>(dataShards), static_cast<std::size_t>(dataShards));
    if (!square) {
        return fail(ErrorKind::LimitExceeded, "parity scratch size overflows");
    }
    auto both = checkedMul(*square, std::size_t{2});
    if (!both) {
        return fail(ErrorKind::LimitExceeded, "parity scratch size overflows");
    }
    return *both;
}

Result<void> ReedSolomon::encode(
    std::span<const std::span<const std::byte>> data,
    std::span<const std::span<std::byte>> parity
) const {
    if (data.size() != data_ || parity.size() != parity_) {
        return fail(ErrorKind::Malformed, "shard count does not match the coder");
    }
    auto length = shardLength(data);
    if (!length) {
        return std::unexpected(length.error());
    }
    for (const auto& shard : parity) {
        if (shard.size() != *length) {
            return fail(ErrorKind::Malformed, "parity shards must share one length");
        }
    }
    for (std::uint32_t row = 0; row < parity_; ++row) {
        std::span<std::byte> out = parity[row];
        for (std::byte& cell : out) {
            cell = std::byte{0};
        }
        for (std::uint32_t column = 0; column < data_; ++column) {
            const std::uint8_t coefficient = cauchyCoefficient(row, column);
            std::span<const std::byte> in = data[column];
            for (std::size_t index = 0; index < *length; ++index) {
                const std::uint8_t mixed =
                    gf::multiply(coefficient, std::to_integer<std::uint8_t>(in[index]));
                out[index] =
                    static_cast<std::byte>(std::to_integer<std::uint8_t>(out[index]) ^ mixed);
            }
        }
    }
    return {};
}

Result<bool> ReedSolomon::verify(
    std::span<const std::span<const std::byte>> data,
    std::span<const std::span<const std::byte>> parity
) const {
    if (data.size() != data_ || parity.size() != parity_) {
        return fail(ErrorKind::Malformed, "shard count does not match the coder");
    }
    auto length = shardLength(data);
    if (!length) {
        return std::unexpected(length.error());
    }
    for (const auto& shard : parity) {
        if (shard.size() != *length) {
            return fail(ErrorKind::Malformed, "parity shards must share one length");
        }
    }
    for (std::uint32_t row = 0; row < parity_; ++row) {
        std::span<const std::byte> expected = parity[row];
        for (std::size_t index = 0; index < *length; ++index) {
            std::uint8_t accumulator = 0;
            for (std::uint32_t column = 0; column < data_; ++column) {
                accumulator ^= gf::multiply(
                    cauchyCoefficient(row, column),
                    std::to_integer<std::uint8_t>(data[column][index])
                );
            }
            if (accumulator != std::to_integer<std::uint8_t>(expected[index])) {
                return false;
            }
        }
    }
    return true;
}

Result<void> ReedSolomon::repair(
    std::span<const std::span<std::byte>> shards,
    std::span<const std::uint32_t> missing,
    std::span<std::byte> scratch
) const {
    if (shards.size() != total()) {
        return fail(ErrorKind::Malformed, "shard count does not match the coder");
    }
    if (shards.empty() || shards[0].size() == 0) {
        return fail(ErrorKind::Malformed, "parity shards must not be empty");
    }
    const std::size_t length = shards[0].size();
    if (length > maxShardBytes) {
        return fail(ErrorKind::LimitExceeded, "parity shard exceeds the size cap");
    }
    for (const auto& shard : shards) {
        if (shard.size() != length) {
            return fail(ErrorKind::Malformed, "parity shards must share one length");
        }
    }
    auto need = scratchBytes(data_, parity_);
    if (!need) {
        return std::unexpected(need.error());
    }
    if (scratch.size() < *need) {
        return fail(ErrorKind::LimitExceeded, "parity scratch is too small");
    }

    std::uint32_t missingCount = 0;
    bool absent[maxTotalShards] = {};
    for (std::uint32_t shard : missing) {
        if (shard >= total()) {
            return fail(ErrorKind::Malformed, "missing shard index is out of range");
        }
        if (absent[shard]) {
            return fail(ErrorKind::Malformed, "missing shard index is duplicated");
        }
        absent[shard] = true;
        ++missingCount;
    }
    if (missingCount == 0) {
        return {};
    }
    if (missingCount > parity_) {
        return fail(ErrorKind::Integrity, "erasures exceed the parity budget");
    }

    bool dataMissing = false;
    for (std::uint32_t index = 0; index < data_; ++index) {
        if (absent[index]) {
            dataMissing = true;
            break;
        }
    }
    if (!dataMissing) {
        for (std::uint32_t row = 0; row < parity_; ++row) {
            if (!absent[data_ + row]) {
                continue;
            }
            std::span<std::byte> out = shards[data_ + row];
            for (std::byte& cell : out) {
                cell = std::byte{0};
            }
            for (std::uint32_t column = 0; column < data_; ++column) {
                const std::uint8_t coefficient = cauchyCoefficient(row, column);
                std::span<const std::byte> in{shards[column].data(), length};
                for (std::size_t index = 0; index < length; ++index) {
                    const std::uint8_t mixed =
                        gf::multiply(coefficient, std::to_integer<std::uint8_t>(in[index]));
                    out[index] =
                        static_cast<std::byte>(std::to_integer<std::uint8_t>(out[index]) ^ mixed);
                }
            }
        }
        return {};
    }

    std::uint32_t rows[maxTotalShards];
    std::uint32_t collected = 0;
    for (std::uint32_t index = 0; index < total() && collected < data_; ++index) {
        if (!absent[index]) {
            rows[collected] = index;
            ++collected;
        }
    }

    const std::size_t side = data_;
    const std::size_t half = side * side;
    for (std::uint32_t row = 0; row < data_; ++row) {
        const std::uint32_t shard = rows[row];
        for (std::uint32_t column = 0; column < data_; ++column) {
            std::uint8_t value = 0;
            if (shard < data_) {
                value = shard == column ? 1 : 0;
            } else {
                value = cauchyCoefficient(shard - data_, column);
            }
            scratch[row * side + column] = static_cast<std::byte>(value);
            scratch[half + row * side + column] = static_cast<std::byte>(row == column ? 1 : 0);
        }
    }
    if (auto inverted = invertMatrix(scratch.first(half * 2), data_); !inverted) {
        return std::unexpected(inverted.error());
    }

    for (std::uint32_t column = 0; column < data_; ++column) {
        if (!absent[column]) {
            continue;
        }
        std::span<std::byte> out = shards[column];
        for (std::byte& cell : out) {
            cell = std::byte{0};
        }
        for (std::uint32_t row = 0; row < data_; ++row) {
            const std::uint8_t factor = std::to_integer<std::uint8_t>(
                scratch[half + static_cast<std::size_t>(column) * side + row]
            );
            if (factor == 0) {
                continue;
            }
            std::span<const std::byte> in{shards[rows[row]].data(), length};
            for (std::size_t index = 0; index < length; ++index) {
                const std::uint8_t mixed =
                    gf::multiply(factor, std::to_integer<std::uint8_t>(in[index]));
                out[index] =
                    static_cast<std::byte>(std::to_integer<std::uint8_t>(out[index]) ^ mixed);
            }
        }
    }
    for (std::uint32_t row = 0; row < parity_; ++row) {
        if (!absent[data_ + row]) {
            continue;
        }
        std::span<std::byte> out = shards[data_ + row];
        for (std::byte& cell : out) {
            cell = std::byte{0};
        }
        for (std::uint32_t column = 0; column < data_; ++column) {
            const std::uint8_t coefficient = cauchyCoefficient(row, column);
            std::span<const std::byte> in{shards[column].data(), length};
            for (std::size_t index = 0; index < length; ++index) {
                const std::uint8_t mixed =
                    gf::multiply(coefficient, std::to_integer<std::uint8_t>(in[index]));
                out[index] =
                    static_cast<std::byte>(std::to_integer<std::uint8_t>(out[index]) ^ mixed);
            }
        }
    }
    return {};
}

}
