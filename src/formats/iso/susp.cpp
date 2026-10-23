#include "formats/iso/susp.hpp"

#include <bit>
#include <cstdint>
#include <vector>

namespace bale::iso {

namespace {

constexpr std::size_t dateLength = 7;

[[nodiscard]] Result<void> followContinuation(
    std::span<const std::byte> entry,
    const File& file,
    std::uint64_t fileSize,
    const Limits& limits,
    SuspState& state,
    std::uint64_t recordOffset,
    std::uint32_t hops
) {
    if (entry.size() != 28) {
        return fail(ErrorKind::Malformed, "bad Rock Ridge continuation entry", recordOffset);
    }
    auto extent = bothLe32(entry.subspan(4, 8));
    if (!extent) {
        return fail(ErrorKind::Malformed, "continuation extent is not both-endian", recordOffset);
    }
    auto offset = bothLe32(entry.subspan(12, 8));
    if (!offset) {
        return fail(ErrorKind::Malformed, "continuation offset is not both-endian", recordOffset);
    }
    auto length = bothLe32(entry.subspan(20, 8));
    if (!length) {
        return fail(ErrorKind::Malformed, "continuation length is not both-endian", recordOffset);
    }
    if (hops >= limits.maxContinuationHops) {
        return fail(ErrorKind::LimitExceeded, "too many Rock Ridge continuations", recordOffset);
    }
    auto budgeted = checkedAdd(state.suspBytes, static_cast<std::uint64_t>(*length));
    if (!budgeted) {
        return fail(ErrorKind::Malformed, "Rock Ridge continuation length overflows", recordOffset);
    }
    state.suspBytes = *budgeted;
    if (state.suspBytes > limits.maxSuspBytes) {
        return fail(
            ErrorKind::LimitExceeded,
            "Rock Ridge continuation exceeds limit",
            recordOffset
        );
    }

    auto start = sectorOffset(*extent, recordOffset);
    if (!start) {
        return tl::unexpected<Error>(start.error());
    }
    auto dataStart = checkedAdd(*start, static_cast<std::uint64_t>(*offset));
    if (!dataStart) {
        return fail(
            ErrorKind::Malformed,
            "Rock Ridge continuation address overflows",
            recordOffset
        );
    }
    auto dataEnd = checkedAdd(*dataStart, static_cast<std::uint64_t>(*length));
    if (!dataEnd) {
        return fail(ErrorKind::Malformed, "Rock Ridge continuation length overflows", recordOffset);
    }
    if (*dataEnd > fileSize) {
        return fail(
            ErrorKind::Truncated,
            "Rock Ridge continuation extends past end of file",
            recordOffset
        );
    }

    auto bytes = checkedCast<std::size_t>(*length);
    if (!bytes) {
        return fail(
            ErrorKind::LimitExceeded,
            "Rock Ridge continuation exceeds limit",
            recordOffset
        );
    }
    std::vector<std::byte> area(*bytes);
    auto read = file.readExactAt(*dataStart, area);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    return parseSystemUse(area, file, fileSize, limits, state, recordOffset, hops + 1);
}

[[nodiscard]] Result<void>
parseNameEntry(std::span<const std::byte> entry, SuspState& state, std::uint64_t recordOffset) {
    if (entry.size() < 5) {
        return fail(ErrorKind::Malformed, "bad Rock Ridge name entry", recordOffset);
    }
    std::uint8_t flags = static_cast<std::uint8_t>(entry[4]);
    if ((flags & 0x06) != 0) {
        return {};
    }
    if (state.namesDone) {
        return fail(ErrorKind::Malformed, "duplicate Rock Ridge name", recordOffset);
    }
    for (std::byte byte : entry.subspan(5)) {
        if (byte == std::byte{0}) {
            return fail(ErrorKind::Malformed, "Rock Ridge name contains NUL", recordOffset);
        }
        if (byte == std::byte{'/'}) {
            return fail(ErrorKind::Malformed, "Rock Ridge name contains a slash", recordOffset);
        }
        state.names.push_back(static_cast<char>(byte));
    }
    state.sawRockRidge = true;
    state.namesDone = (flags & 0x01) == 0;
    return {};
}

[[nodiscard]] Result<void>
parseLinkEntry(std::span<const std::byte> entry, SuspState& state, std::uint64_t recordOffset) {
    if (entry.size() < 5) {
        return fail(ErrorKind::Malformed, "bad Rock Ridge symlink entry", recordOffset);
    }
    auto components = entry.subspan(5);
    std::size_t at = 0;
    while (at < components.size()) {
        if (at + 2 > components.size()) {
            return fail(ErrorKind::Malformed, "bad Rock Ridge symlink component", recordOffset);
        }
        std::uint8_t flags = static_cast<std::uint8_t>(components[at]);
        std::size_t length =
            static_cast<std::size_t>(static_cast<std::uint8_t>(components[at + 1]));
        if (at + 2 + length > components.size()) {
            return fail(ErrorKind::Malformed, "bad Rock Ridge symlink component", recordOffset);
        }
        auto text = components.subspan(at + 2, length);
        at += 2 + length;

        std::string part;
        if ((flags & 0x08) != 0) {
            if (!state.link.empty() || state.linkAbsolute) {
                return fail(ErrorKind::Malformed, "bad Rock Ridge symlink root", recordOffset);
            }
            state.linkAbsolute = true;
            continue;
        }
        if ((flags & 0x04) != 0) {
            part = "..";
        } else if ((flags & 0x02) != 0) {
            part = ".";
        } else {
            for (std::byte byte : text) {
                if (byte == std::byte{0}) {
                    return fail(ErrorKind::Malformed, "symlink target contains NUL", recordOffset);
                }
                if (byte == std::byte{'/'}) {
                    return fail(
                        ErrorKind::Malformed,
                        "symlink target contains a slash",
                        recordOffset
                    );
                }
            }
            part.assign(reinterpret_cast<const char*>(text.data()), text.size());
        }
        if (!state.link.empty()) {
            state.link.push_back('/');
        }
        state.link.append(part);
    }
    state.sawRockRidge = true;
    return {};
}

[[nodiscard]] Result<void>
parseTimeEntry(std::span<const std::byte> entry, SuspState& state, std::uint64_t recordOffset) {
    if (entry.size() < 5) {
        return fail(ErrorKind::Malformed, "bad Rock Ridge timestamp entry", recordOffset);
    }
    std::uint8_t flags = static_cast<std::uint8_t>(entry[4]);
    auto stamps = entry.subspan(5);
    unsigned count = static_cast<unsigned>(std::popcount(static_cast<unsigned>(flags) & 0x7FU));
    bool wide = stamps.size() == static_cast<std::size_t>(count) * 17;
    bool narrow = stamps.size() == static_cast<std::size_t>(count) * dateLength;
    if (!wide && !narrow) {
        return fail(ErrorKind::Malformed, "bad Rock Ridge timestamp block", recordOffset);
    }
    if ((flags & 0x02) == 0) {
        state.sawRockRidge = true;
        return {};
    }

    unsigned slot = 0;
    for (unsigned bit = 0; bit < 7; ++bit) {
        if ((flags & (1U << bit)) == 0) {
            continue;
        }
        if (bit == 1) {
            auto stamp = stamps.subspan(
                static_cast<std::size_t>(slot) * (wide ? 17 : dateLength),
                wide ? 17 : dateLength
            );
            auto seconds = wide ? longTimeToUnix(stamp) : shortTimeToUnix(stamp);
            if (!seconds) {
                return fail(
                    ErrorKind::Malformed,
                    "Rock Ridge timestamp out of range",
                    recordOffset
                );
            }
            state.stampSeconds = *seconds;
            state.hasStamp = true;
            break;
        }
        ++slot;
    }
    state.sawRockRidge = true;
    return {};
}

}

[[nodiscard]] Result<void> parseSystemUse(
    std::span<const std::byte> area,
    const File& file,
    std::uint64_t fileSize,
    const Limits& limits,
    SuspState& state,
    std::uint64_t recordOffset,
    std::uint32_t hops
) {
    std::size_t at = 0;
    while (at < area.size()) {
        if (area.size() - at == 1) {
            if (area[at] != std::byte{0}) {
                return fail(ErrorKind::Malformed, "bad ISO system use padding", recordOffset);
            }
            return {};
        }
        if (area.size() - at < 4) {
            return fail(ErrorKind::Malformed, "truncated Rock Ridge entry", recordOffset);
        }
        std::string_view signature(reinterpret_cast<const char*>(area.data() + at), 2);
        std::size_t length = static_cast<std::size_t>(static_cast<std::uint8_t>(area[at + 2]));
        if (length < 4 || at + length > area.size()) {
            return fail(ErrorKind::Malformed, "bad Rock Ridge entry length", recordOffset);
        }
        if (area[at + 3] != std::byte{1}) {
            return fail(ErrorKind::Malformed, "unsupported Rock Ridge entry version", recordOffset);
        }
        auto entry = area.subspan(at, length);
        at += length;

        if (signature == "SP") {
            if (length != 7 || entry[4] != std::byte{0xBE} || entry[5] != std::byte{0xEF}) {
                return fail(ErrorKind::Malformed, "bad SUSP magic", recordOffset);
            }
        } else if (signature == "CE") {
            auto followed =
                followContinuation(entry, file, fileSize, limits, state, recordOffset, hops);
            if (!followed) {
                return followed;
            }
        } else if (signature == "PX") {
            if (length != 36) {
                return fail(ErrorKind::Malformed, "bad Rock Ridge attributes entry", recordOffset);
            }
            auto mode = bothLe32(entry.subspan(4, 8));
            if (!mode) {
                return fail(ErrorKind::Malformed, "POSIX mode is not both-endian", recordOffset);
            }
            state.mode = *mode;
            state.hasMode = true;
            state.sawRockRidge = true;
        } else if (signature == "PN") {
            if (length != 20) {
                return fail(ErrorKind::Malformed, "bad Rock Ridge device entry", recordOffset);
            }
            state.sawRockRidge = true;
        } else if (signature == "NM") {
            auto named = parseNameEntry(entry, state, recordOffset);
            if (!named) {
                return named;
            }
        } else if (signature == "SL") {
            auto linked = parseLinkEntry(entry, state, recordOffset);
            if (!linked) {
                return linked;
            }
        } else if (signature == "TF") {
            auto timed = parseTimeEntry(entry, state, recordOffset);
            if (!timed) {
                return timed;
            }
        } else if (signature == "CL" || signature == "PL" || signature == "RE") {
            state.relocated = true;
        } else if (signature == "ST") {
            return {};
        }
    }
    return {};
}

}
