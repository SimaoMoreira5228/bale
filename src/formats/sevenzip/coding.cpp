#include "formats/sevenzip/coding.hpp"

#include "base/checked.hpp"

namespace bale::sevenzip {

Result<std::uint64_t> readNumber(ByteReader& reader) {
    auto first = reader.u8();
    if (!first) {
        return tl::unexpected<Error>(first.error());
    }

    unsigned mask = 0x80;
    std::uint64_t value = 0;
    for (int index = 0; index < 8; ++index) {
        if ((*first & mask) == 0) {
            std::uint64_t high = *first & (mask - 1);
            auto shifted = checkedMul(high, std::uint64_t{1} << (index * 8));
            if (!shifted) {
                return fail(ErrorKind::Malformed, "7z number overflows", reader.offset());
            }

            auto total = checkedAdd(value, *shifted);
            if (!total) {
                return fail(ErrorKind::Malformed, "7z number overflows", reader.offset());
            }
            return *total;
        }

        auto next = reader.u8();
        if (!next) {
            return tl::unexpected<Error>(next.error());
        }

        value |= std::uint64_t{*next} << (index * 8);
        mask >>= 1;
    }

    // NOTE: a first byte of 0xFF stores the value in the next eight bytes.
    // The loop above already consumed them little-endian.
    return value;
}

Result<std::uint8_t> readId(ByteReader& reader) {
    auto id = reader.u8();
    if (!id) {
        return tl::unexpected<Error>(id.error());
    }
    return *id;
}

Result<void> expectId(ByteReader& reader, std::uint8_t expected, std::string_view what) {
    auto id = readId(reader);
    if (!id) {
        return tl::unexpected<Error>(id.error());
    }
    if (*id != expected) {
        return fail(ErrorKind::Malformed, what, reader.offset());
    }
    return {};
}

bool bitSet(std::span<const std::byte> bits, std::uint64_t index) {
    std::uint8_t byte = std::to_integer<std::uint8_t>(bits[index / 8]);
    return (byte & (0x80 >> (index % 8))) != 0;
}

Result<std::vector<std::byte>> readBits(ByteReader& reader, std::uint64_t count) {
    auto bytes = (count + 7) / 8;
    auto size = checkedCast<std::size_t>(bytes);
    if (!size) {
        return fail(ErrorKind::LimitExceeded, "7z bit vector too large", reader.offset());
    }

    auto taken = reader.bytes(*size);
    if (!taken) {
        return tl::unexpected<Error>(taken.error());
    }
    return std::vector<std::byte>(taken->begin(), taken->end());
}

Result<std::vector<std::optional<std::uint32_t>>>
readDigests(ByteReader& reader, std::uint64_t count, const Limits& limits) {
    if (count > limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "7z digest count exceeds limit", reader.offset());
    }

    auto defined = readId(reader);
    if (!defined) {
        return tl::unexpected<Error>(defined.error());
    }

    std::vector<std::byte> bits;
    if (*defined == 0) {
        auto read = readBits(reader, count);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        bits = std::move(*read);
    } else if (*defined != 1) {
        return fail(ErrorKind::Malformed, "7z digest flag must be 0 or 1", reader.offset());
    }

    std::vector<std::optional<std::uint32_t>> digests;
    digests.reserve(checkedCast<std::size_t>(count).value_or(0));
    for (std::uint64_t index = 0; index < count; ++index) {
        bool present = *defined != 0 || bitSet(bits, index);
        if (!present) {
            digests.emplace_back(std::nullopt);
            continue;
        }

        auto value = reader.u32le();
        if (!value) {
            return tl::unexpected<Error>(value.error());
        }
        digests.emplace_back(*value);
    }
    return digests;
}

Result<void> skipProperties(ByteReader& reader, std::uint64_t offset) {
    while (true) {
        auto kind = readId(reader);
        if (!kind) {
            return tl::unexpected<Error>(kind.error());
        }
        if (*kind == nidEnd) {
            return {};
        }

        auto size = readNumber(reader);
        if (!size) {
            return tl::unexpected<Error>(size.error());
        }
        if (*size > reader.remaining()) {
            return fail(ErrorKind::Malformed, "7z archive property overruns the header", offset);
        }

        auto skipped = reader.skip(checkedCast<std::size_t>(*size).value_or(reader.remaining()));
        if (!skipped) {
            return tl::unexpected<Error>(skipped.error());
        }
    }
}

Result<std::uint64_t> folderOutputSize(const Folder& folder, std::uint64_t offset) {
    if (folder.finalOutStream >= folder.unpackSizes.size()) {
        return fail(ErrorKind::Malformed, "7z folder unpack sizes do not match", offset);
    }
    return folder.unpackSizes[folder.finalOutStream];
}
}
