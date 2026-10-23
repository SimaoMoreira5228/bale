#include "formats/ar/header.hpp"

#include "base/checked.hpp"

#include <algorithm>
#include <limits>

namespace bale::ar {

namespace {

std::string_view
fieldText(std::span<const std::byte> header, std::size_t offset, std::size_t length) {
    auto bytes = header.subspan(offset, length);
    std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());

    while (!text.empty() && text.back() == ' ') {
        text.remove_suffix(1);
    }

    return text;
}

Result<std::uint64_t> parseDecimalField(
    std::span<const std::byte> header,
    std::size_t offset,
    std::size_t length,
    std::uint64_t at
) {
    auto text = fieldText(header, offset, length);
    if (text.empty()) {
        return 0;
    }

    std::uint64_t value = 0;
    for (char digit : text) {
        if (digit < '0' || digit > '9') {
            return fail(ErrorKind::Malformed, "invalid ar decimal field", at + offset);
        }

        auto scaled = checkedMul(value, 10u);
        if (!scaled) {
            return fail(ErrorKind::Malformed, "ar numeric field overflows", at + offset);
        }

        auto next = checkedAdd(*scaled, static_cast<std::uint64_t>(digit - '0'));
        if (!next) {
            return fail(ErrorKind::Malformed, "ar numeric field overflows", at + offset);
        }
        value = *next;
    }
    return value;
}

Result<std::uint32_t> parseOctalField(
    std::span<const std::byte> header,
    std::size_t offset,
    std::size_t length,
    std::uint64_t at
) {
    auto text = fieldText(header, offset, length);
    if (text.empty()) {
        return 0;
    }

    std::uint64_t value = 0;
    for (char digit : text) {
        if (digit < '0' || digit > '7') {
            return fail(ErrorKind::Malformed, "invalid ar mode field", at + offset);
        }

        if (value > (std::numeric_limits<std::uint64_t>::max() >> 3)) {
            return fail(ErrorKind::Malformed, "ar numeric field overflows", at + offset);
        }
        value = (value << 3) | static_cast<std::uint64_t>(digit - '0');
    }

    auto narrowed = checkedCast<std::uint32_t>(value);
    if (!narrowed) {
        return fail(ErrorKind::Malformed, "ar mode field out of range", at + offset);
    }
    return *narrowed;
}

}

bool looksLikeAr(std::span<const std::byte> head) {
    if (head.size() < magic.size()) {
        return false;
    }

    std::string_view text(reinterpret_cast<const char*>(head.data()), magic.size());
    return text == magic;
}

Result<Member> parseMember(std::span<const std::byte, headerSize> header, std::uint64_t offset) {
    auto body = std::span<const std::byte>(header);
    if (!std::ranges::equal(body.subspan(terminatorOffset, terminator.size()), terminator)) {
        return fail(ErrorKind::Malformed, "ar member header terminator mismatch", offset);
    }

    auto date = parseDecimalField(body, dateOffset, dateLength, offset);
    if (!date) {
        return tl::unexpected<Error>(date.error());
    }

    auto uid = parseDecimalField(body, uidOffset, uidLength, offset);
    if (!uid) {
        return tl::unexpected<Error>(uid.error());
    }

    auto gid = parseDecimalField(body, gidOffset, gidLength, offset);
    if (!gid) {
        return tl::unexpected<Error>(gid.error());
    }

    auto mode = parseOctalField(body, modeOffset, modeLength, offset);
    if (!mode) {
        return tl::unexpected<Error>(mode.error());
    }

    auto size = parseDecimalField(body, sizeOffset, sizeLength, offset);
    if (!size) {
        return tl::unexpected<Error>(size.error());
    }

    auto seconds = checkedCast<std::int64_t>(*date);
    if (!seconds) {
        return fail(ErrorKind::Malformed, "ar timestamp out of range", offset + dateOffset);
    }

    auto data = checkedAdd(offset, std::uint64_t{headerSize});
    if (!data) {
        return fail(ErrorKind::Malformed, "ar member offset overflows", offset);
    }

    Member member;
    member.rawName = fieldText(body, nameOffset, nameLength);
    member.headerOffset = offset;
    member.dataOffset = *data;
    member.size = *size;
    member.mtimeSeconds = *seconds;
    member.uid = *uid;
    member.gid = *gid;
    member.mode = *mode;
    return member;
}

}
