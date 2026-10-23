#include "format/tlv.hpp"

#include "base/endian.hpp"

#include <algorithm>
#include <array>
#include <bit>

namespace bale {

Result<Leb128> decodeLeb128(std::span<const std::byte> data, std::uint64_t baseOffset) {
    std::uint64_t value = 0;
    std::size_t limit = std::min(data.size(), maxLeb128Size);

    for (std::size_t index = 0; index < limit; ++index) {
        auto byte = std::to_integer<std::uint8_t>(data[index]);
        std::uint64_t group = byte & 0x7FU;
        if (index == maxLeb128Size - 1 && group > 1) {
            return fail(ErrorKind::Malformed, "ULEB128 value exceeds 64 bits", baseOffset + index);
        }
        value |= group << (7 * index);

        if ((byte & 0x80U) != 0) {
            continue;
        }
        if (byte == 0 && index > 0) {
            return fail(ErrorKind::Malformed, "non-minimal ULEB128 encoding", baseOffset + index);
        }
        return Leb128{
            .value = value,
            .size = index + 1,
        };
    }

    if (data.size() >= maxLeb128Size) {
        return fail(
            ErrorKind::Malformed,
            "ULEB128 encoding longer than 10 bytes",
            baseOffset + maxLeb128Size - 1
        );
    }
    return fail(ErrorKind::Truncated, "unexpected end of ULEB128", baseOffset + data.size());
}

std::size_t encodeLeb128(std::uint64_t value, std::span<std::byte, maxLeb128Size> target) {
    std::size_t size = 0;
    do {
        auto group = static_cast<std::uint8_t>(value & 0x7FU);
        value >>= 7;
        if (value != 0) {
            group = static_cast<std::uint8_t>(group | 0x80U);
        }
        target[size] = std::byte{group};
        ++size;
    } while (value != 0);
    return size;
}

void appendLeb128(std::vector<std::byte>& out, std::uint64_t value) {
    std::array<std::byte, maxLeb128Size> encoded{};
    std::size_t size = encodeLeb128(value, encoded);
    out.insert(out.end(), encoded.begin(), encoded.begin() + static_cast<std::ptrdiff_t>(size));
}

Result<bool> TlvReader::next(TlvField& field) {
    if (pos_ == data_.size()) {
        return false;
    }

    std::uint64_t fieldOffset = base_ + pos_;
    auto key = decodeLeb128(data_.subspan(pos_), fieldOffset);
    if (!key) {
        return tl::unexpected<Error>(key.error());
    }

    std::uint64_t number = key->value >> 1;
    if (number == 0) {
        return fail(ErrorKind::Malformed, "TLV field number zero", fieldOffset);
    }
    if (number > maxTlvFieldNumber) {
        return fail(ErrorKind::Malformed, "TLV field number out of range", fieldOffset);
    }
    if (number <= lastNumber_) {
        return fail(
            ErrorKind::Malformed,
            "TLV fields not in strictly increasing order",
            fieldOffset
        );
    }

    std::size_t lengthPos = pos_ + key->size;
    auto length = decodeLeb128(data_.subspan(lengthPos), base_ + lengthPos);
    if (!length) {
        return tl::unexpected<Error>(length.error());
    }

    std::size_t valuePos = lengthPos + length->size;
    std::uint64_t available = data_.size() - valuePos;
    if (length->value > available) {
        return fail(
            ErrorKind::Truncated,
            "TLV field value extends past end of structure",
            base_ + valuePos
        );
    }
    auto valueSize = static_cast<std::size_t>(length->value);

    field.number = static_cast<std::uint32_t>(number);
    field.criticality = (key->value & 1) != 0 ? Criticality::Critical : Criticality::Noncritical;
    field.value = data_.subspan(valuePos, valueSize);
    field.offset = fieldOffset;

    lastNumber_ = field.number;
    pos_ = valuePos + valueSize;
    return true;
}

Result<void> skipUnknownField(const TlvField& field) {
    if (field.criticality == Criticality::Critical) {
        return fail(ErrorKind::Unsupported, "unknown critical TLV field", field.offset);
    }
    return {};
}

Result<std::uint64_t> decodeTlvUnsigned(const TlvField& field) {
    auto decoded = decodeLeb128(field.value, field.offset);
    if (!decoded) {
        return tl::unexpected<Error>(decoded.error());
    }
    if (decoded->size != field.value.size()) {
        return fail(ErrorKind::Malformed, "trailing bytes after TLV integer", field.offset);
    }
    return decoded->value;
}

Result<std::int64_t> decodeTlvSigned64(const TlvField& field) {
    if (field.value.size() != sizeof(std::int64_t)) {
        return fail(ErrorKind::Malformed, "TLV signed integer is not 8 bytes", field.offset);
    }
    return std::bit_cast<std::int64_t>(loadLe<std::uint64_t>(field.value.data()));
}

Result<void> requireCriticality(const TlvField& field, Criticality expected) {
    if (field.criticality != expected) {
        return fail(ErrorKind::Malformed, "TLV field has the wrong criticality", field.offset);
    }
    return {};
}

Result<TlvListReader> TlvListReader::open(const TlvField& field, std::uint64_t maxCount) {
    auto count = decodeLeb128(field.value, field.offset);
    if (!count) {
        return tl::unexpected<Error>(count.error());
    }
    if (count->value > maxCount) {
        return fail(ErrorKind::LimitExceeded, "TLV list has too many elements", field.offset);
    }
    if (count->value > field.value.size() - count->size) {
        return fail(
            ErrorKind::Truncated,
            "TLV list count exceeds the bytes available",
            field.offset
        );
    }
    return TlvListReader(
        field.value.subspan(count->size),
        field.offset + count->size,
        count->value
    );
}

Result<bool> TlvListReader::next(std::span<const std::byte>& element, std::uint64_t& offset) {
    if (read_ == count_) {
        if (pos_ != data_.size()) {
            return fail(ErrorKind::Malformed, "trailing bytes after TLV list", base_ + pos_);
        }
        return false;
    }

    auto length = decodeLeb128(data_.subspan(pos_), base_ + pos_);
    if (!length) {
        return tl::unexpected<Error>(length.error());
    }

    std::size_t elementPos = pos_ + length->size;
    if (length->value > data_.size() - elementPos) {
        return fail(
            ErrorKind::Truncated,
            "TLV list element extends past end of list",
            base_ + elementPos
        );
    }

    auto size = static_cast<std::size_t>(length->value);
    element = data_.subspan(elementPos, size);
    offset = base_ + elementPos;
    pos_ = elementPos + size;
    ++read_;
    return true;
}

void appendTlvListElement(std::vector<std::byte>& out, std::span<const std::byte> element) {
    appendLeb128(out, element.size());
    out.insert(out.end(), element.begin(), element.end());
}

Result<void>
TlvWriter::bytes(std::uint32_t number, Criticality criticality, std::span<const std::byte> value) {
    auto started = beginField(number, criticality, value.size());
    if (!started) {
        return started;
    }

    out_->insert(out_->end(), value.begin(), value.end());
    return {};
}

Result<void>
TlvWriter::unsignedValue(std::uint32_t number, Criticality criticality, std::uint64_t value) {
    std::array<std::byte, maxLeb128Size> encoded{};
    std::size_t size = encodeLeb128(value, encoded);
    return bytes(number, criticality, std::span(encoded).first(size));
}

Result<void>
TlvWriter::signed64(std::uint32_t number, Criticality criticality, std::int64_t value) {
    std::array<std::byte, sizeof(std::int64_t)> encoded{};
    storeLe(encoded.data(), std::bit_cast<std::uint64_t>(value));
    return bytes(number, criticality, encoded);
}

Result<void>
TlvWriter::beginField(std::uint32_t number, Criticality criticality, std::uint64_t length) {
    if (number == 0 || number > maxTlvFieldNumber) {
        return fail(ErrorKind::Malformed, "TLV field number out of range");
    }
    if (number <= lastNumber_) {
        return fail(ErrorKind::Malformed, "TLV fields not in strictly increasing order");
    }

    std::uint64_t critical = criticality == Criticality::Critical ? 1 : 0;
    appendLeb128(*out_, (std::uint64_t{number} << 1) | critical);
    appendLeb128(*out_, length);
    lastNumber_ = number;
    return {};
}

}
