#include "formats/iso/header.hpp"

#include <array>
#include <chrono>
#include <string>

namespace bale::iso {

namespace {

constexpr std::int64_t secondsPerDay = 86400;
constexpr std::int32_t secondsPerMinute = 60;
constexpr std::int64_t minutesPerOffsetStep = 15;

[[nodiscard]] std::optional<std::int64_t> civilToUnix(
    int year,
    unsigned month,
    unsigned day,
    unsigned hour,
    unsigned minute,
    unsigned second
) {
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) {
        return std::nullopt;
    }

    std::chrono::year_month_day date{
        std::chrono::year{year},
        std::chrono::month{month},
        std::chrono::day{day},
    };
    if (!date.ok()) {
        return std::nullopt;
    }

    auto days = std::chrono::sys_days(date).time_since_epoch().count();
    return days * secondsPerDay + static_cast<std::int64_t>(hour) * 3600 +
        static_cast<std::int64_t>(minute) * secondsPerMinute + second;
}

[[nodiscard]] bool allDigits(std::span<const std::byte> text) {
    for (std::byte byte : text) {
        auto digit = static_cast<char>(byte);
        if (digit < '0' || digit > '9') {
            return false;
        }
    }
    return true;
}

}

bool looksLikePrimaryDescriptor(std::span<const std::byte> probe) {
    if (probe.size() < 7) {
        return false;
    }
    if (probe[0] != std::byte{descriptorPrimary}) {
        return false;
    }
    std::string_view magic(reinterpret_cast<const char*>(probe.data() + 1), volumeMagic.size());
    if (magic != volumeMagic) {
        return false;
    }
    return probe[6] == std::byte{1};
}

Result<bool> isIsoImage(const File& file, std::uint64_t fileSize) {
    if (fileSize < minImageSize) {
        return false;
    }

    std::array<std::byte, 7> probe{};
    auto read = file.readExactAt(systemSectors * sectorSize, probe);
    if (!read) {
        if (read.error().kind == ErrorKind::Io) {
            return std::unexpected(read.error());
        }
        return false;
    }
    return looksLikePrimaryDescriptor(probe);
}

std::uint16_t readLe16(std::span<const std::byte> bytes) {
    return static_cast<std::uint16_t>(static_cast<unsigned>(bytes[0])) |
        static_cast<std::uint16_t>(static_cast<unsigned>(bytes[1]) << 8);
}

std::uint32_t readLe32(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (int shift = 0; shift < 32; shift += 8) {
        value |= static_cast<std::uint32_t>(bytes[static_cast<std::size_t>(shift) / 8]) << shift;
    }
    return value;
}

std::uint32_t readBe32(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (std::byte byte : bytes.first(4)) {
        value = (value << 8) | static_cast<std::uint8_t>(byte);
    }
    return value;
}

std::optional<std::uint32_t> bothLe32(std::span<const std::byte> bytes) {
    std::uint32_t little = readLe32(bytes);
    std::uint32_t big = readBe32(bytes.subspan(4, 4));
    if (little != big) {
        return std::nullopt;
    }
    return little;
}

Result<std::uint64_t> sectorOffset(std::uint32_t sector, std::uint64_t at) {
    auto offset = checkedMul<std::uint64_t>(sector, sectorSize);
    if (!offset) {
        return fail(ErrorKind::Malformed, "ISO sector address overflows", at);
    }
    return *offset;
}

std::optional<std::int64_t> shortTimeToUnix(std::span<const std::byte> date) {
    if (date.size() != 7) {
        return std::nullopt;
    }

    int year = static_cast<int>(static_cast<std::uint8_t>(date[0])) + 1900;
    auto values = std::array<unsigned, 5>{
        static_cast<unsigned>(date[1]),
        static_cast<unsigned>(date[2]),
        static_cast<unsigned>(date[3]),
        static_cast<unsigned>(date[4]),
        static_cast<unsigned>(date[5]),
    };
    auto civil = civilToUnix(year, values[0], values[1], values[2], values[3], values[4]);
    if (!civil) {
        return std::nullopt;
    }
    auto shift =
        static_cast<std::int64_t>(static_cast<std::int8_t>(date[6])) * minutesPerOffsetStep * 60;
    return *civil - shift;
}

std::optional<std::int64_t> longTimeToUnix(std::span<const std::byte> date) {
    if (date.size() != 17 || !allDigits(date.first(16))) {
        return std::nullopt;
    }

    auto digits = [&](std::size_t at, std::size_t count) {
        int value = 0;
        for (std::size_t index = 0; index < count; ++index) {
            auto byte = static_cast<unsigned>(date[at + index]);
            value = value * 10 + static_cast<int>(byte) - '0';
        }
        return value;
    };
    auto civil = civilToUnix(
        digits(0, 4),
        static_cast<unsigned>(digits(4, 2)),
        static_cast<unsigned>(digits(6, 2)),
        static_cast<unsigned>(digits(8, 2)),
        static_cast<unsigned>(digits(10, 2)),
        static_cast<unsigned>(digits(12, 2))
    );
    if (!civil) {
        return std::nullopt;
    }
    auto shift =
        static_cast<std::int64_t>(static_cast<std::int8_t>(date[16])) * minutesPerOffsetStep * 60;
    return *civil - shift;
}

bool isJolietEscape(std::span<const std::byte> escapes) {
    if (escapes.size() < 3) {
        return false;
    }
    if (static_cast<char>(escapes[0]) != '%' || static_cast<char>(escapes[1]) != '/') {
        return false;
    }
    char level = static_cast<char>(escapes[2]);
    return level == 'C' || level == 'E' || level == '@';
}

std::string_view stripVersionSuffix(std::string_view name) {
    auto version = name.rfind(';');
    if (version != std::string_view::npos) {
        bool digits = version + 1 < name.size();
        for (std::size_t index = version + 1; digits && index < name.size(); ++index) {
            if (name[index] < '0' || name[index] > '9') {
                digits = false;
            }
        }
        if (digits) {
            name.remove_suffix(name.size() - version);
        }
    }
    while (!name.empty() && name.back() == '.') {
        name.remove_suffix(1);
    }
    return name;
}

}
