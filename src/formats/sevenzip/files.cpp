#include "formats/sevenzip/header.hpp"

#include "base/checked.hpp"
#include "formats/sevenzip/coding.hpp"

#include <string>
#include <vector>

namespace bale::sevenzip {

namespace {

constexpr std::uint64_t fileTimeToUnixOffset = 11'644'473'600'000'000'000ULL;

std::optional<std::int64_t> fileTimeToUnix(std::uint64_t fileTime) {
    auto scaled = checkedMul(fileTime, std::uint64_t{100});
    if (!scaled || *scaled < fileTimeToUnixOffset) {
        return std::nullopt;
    }

    std::uint64_t sinceEpoch = *scaled - fileTimeToUnixOffset;
    if (sinceEpoch > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        return std::nullopt;
    }
    return static_cast<std::int64_t>(sinceEpoch);
}

void appendUtf8(std::string& out, char32_t point) {
    if (point < 0x80) {
        out.push_back(static_cast<char>(point));
    } else if (point < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (point >> 6)));
        out.push_back(static_cast<char>(0x80 | (point & 0x3F)));
    } else if (point < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (point >> 12)));
        out.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (point & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (point >> 18)));
        out.push_back(static_cast<char>(0x80 | ((point >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (point & 0x3F)));
    }
}

Result<std::string> readName(ByteReader& reader, std::uint64_t maxBytes, const Limits& limits) {
    auto offset = reader.offset();
    if (maxBytes > reader.remaining()) {
        return fail(ErrorKind::Malformed, "7z names overrun the header", offset);
    }

    std::string name;
    std::uint64_t consumed = 0;
    char32_t high = 0;
    bool pendingHigh = false;
    while (consumed < maxBytes) {
        if (maxBytes - consumed < 2) {
            return fail(ErrorKind::Malformed, "7z name has a trailing byte", offset);
        }

        auto unit = reader.u16le();
        if (!unit) {
            return std::unexpected(unit.error());
        }
        consumed += 2;

        char16_t part = *unit;
        if (part >= 0xD800 && part <= 0xDBFF) {
            if (pendingHigh) {
                appendUtf8(name, 0xFFFD);
            }
            high = part;
            pendingHigh = true;
            continue;
        }
        if (part >= 0xDC00 && part <= 0xDFFF) {
            if (!pendingHigh) {
                appendUtf8(name, 0xFFFD);
                continue;
            }
            pendingHigh = false;
            appendUtf8(name, 0x10000 + ((high - 0xD800) << 10) + (part - 0xDC00));
            continue;
        }
        if (pendingHigh) {
            appendUtf8(name, 0xFFFD);
            pendingHigh = false;
        }
        if (part == 0) {
            if (name.size() > limits.maxNameBytes) {
                return fail(ErrorKind::LimitExceeded, "7z entry name exceeds limit", offset);
            }
            return name;
        }
        appendUtf8(name, part);
    }

    return fail(ErrorKind::Malformed, "7z name is not terminated", offset);
}

Result<std::vector<std::string>>
readNames(ByteReader& reader, std::uint64_t files, std::uint64_t propSize, const Limits& limits) {
    auto offset = reader.offset();
    std::uint64_t start = reader.position();
    auto external = readId(reader);
    if (!external) {
        return std::unexpected(external.error());
    }
    if (*external != 0) {
        return fail(
            ErrorKind::Unsupported,
            "7z names in an external stream are not supported",
            reader.offset()
        );
    }

    std::vector<std::string> names;
    names.reserve(checkedCast<std::size_t>(files).value_or(0));
    for (std::uint64_t index = 0; index < files; ++index) {
        auto name = readName(reader, propSize - (reader.position() - start), limits);
        if (!name) {
            return std::unexpected(name.error());
        }
        names.push_back(std::move(*name));
    }
    if (reader.position() - start != propSize) {
        return fail(ErrorKind::Malformed, "7z names do not fill their property", offset);
    }
    return names;
}

Result<void> readTimes(
    ByteReader& reader,
    std::uint64_t files,
    std::uint64_t propSize,
    std::vector<FileMeta>& metas
) {
    auto offset = reader.offset();
    std::uint64_t start = reader.position();

    auto defined = readId(reader);
    if (!defined) {
        return std::unexpected(defined.error());
    }
    if (*defined != 0 && *defined != 1) {
        return fail(ErrorKind::Malformed, "7z time flag must be 0 or 1", offset);
    }

    std::vector<std::byte> bits;
    if (*defined == 0) {
        auto read = readBits(reader, files);
        if (!read) {
            return std::unexpected(read.error());
        }
        bits = std::move(*read);
    }

    auto external = readId(reader);
    if (!external) {
        return std::unexpected(external.error());
    }
    if (*external != 0) {
        return fail(
            ErrorKind::Unsupported,
            "7z times in an external stream are not supported",
            reader.offset()
        );
    }

    for (std::uint64_t index = 0; index < files; ++index) {
        bool present = *defined != 0 || bitSet(bits, index);
        if (!present) {
            continue;
        }

        auto stamp = reader.u64le();
        if (!stamp) {
            return std::unexpected(stamp.error());
        }
        metas[index].mtimeNanoseconds = fileTimeToUnix(*stamp);
    }

    if (reader.position() - start != propSize) {
        return fail(ErrorKind::Malformed, "7z times do not fill their property", offset);
    }
    return {};
}

Result<void> readAttributes(
    ByteReader& reader,
    std::uint64_t files,
    std::uint64_t propSize,
    std::vector<FileMeta>& metas
) {
    auto offset = reader.offset();
    std::uint64_t start = reader.position();

    auto defined = readId(reader);
    if (!defined) {
        return std::unexpected(defined.error());
    }
    if (*defined != 0 && *defined != 1) {
        return fail(ErrorKind::Malformed, "7z attribute flag must be 0 or 1", offset);
    }

    std::vector<std::byte> bits;
    if (*defined == 0) {
        auto read = readBits(reader, files);
        if (!read) {
            return std::unexpected(read.error());
        }
        bits = std::move(*read);
    }

    auto external = readId(reader);
    if (!external) {
        return std::unexpected(external.error());
    }
    if (*external != 0) {
        return fail(
            ErrorKind::Unsupported,
            "7z attributes in an external stream are not supported",
            reader.offset()
        );
    }

    for (std::uint64_t index = 0; index < files; ++index) {
        bool present = *defined != 0 || bitSet(bits, index);
        if (!present) {
            continue;
        }

        auto attributes = reader.u32le();
        if (!attributes) {
            return std::unexpected(attributes.error());
        }
        std::uint32_t mode = *attributes >> 16;
        if (mode != 0) {
            metas[index].mode = mode;
        }
    }

    if (reader.position() - start != propSize) {
        return fail(ErrorKind::Malformed, "7z attributes do not fill their property", offset);
    }
    return {};
}

Result<void> readStartPositions(
    ByteReader& reader,
    std::uint64_t files,
    std::uint64_t propSize,
    std::vector<FileMeta>& metas
) {
    auto offset = reader.offset();
    std::uint64_t start = reader.position();

    auto defined = readId(reader);
    if (!defined) {
        return std::unexpected(defined.error());
    }
    if (*defined != 0 && *defined != 1) {
        return fail(ErrorKind::Malformed, "7z start flag must be 0 or 1", offset);
    }

    std::vector<std::byte> bits;
    if (*defined == 0) {
        auto read = readBits(reader, files);
        if (!read) {
            return std::unexpected(read.error());
        }
        bits = std::move(*read);
    }

    auto external = readId(reader);
    if (!external) {
        return std::unexpected(external.error());
    }
    if (*external != 0) {
        return fail(
            ErrorKind::Unsupported,
            "7z start positions in an external stream are not supported",
            reader.offset()
        );
    }

    for (std::uint64_t index = 0; index < files; ++index) {
        bool present = *defined != 0 || bitSet(bits, index);
        if (!present) {
            continue;
        }

        auto position = reader.u64le();
        if (!position) {
            return std::unexpected(position.error());
        }
        metas[index].startPos = *position;
    }

    if (reader.position() - start != propSize) {
        return fail(ErrorKind::Malformed, "7z start positions do not fill their property", offset);
    }
    return {};
}

}

Result<void> readFilesInfo(ByteReader& reader, Model& model, const Limits& limits) {
    auto offset = reader.offset();
    auto numFiles = readNumber(reader);
    if (!numFiles) {
        return std::unexpected(numFiles.error());
    }
    if (*numFiles > limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "7z entry count exceeds limit", offset);
    }
    model.files.resize(checkedCast<std::size_t>(*numFiles).value_or(0));

    std::uint64_t emptyCount = 0;
    while (true) {
        auto prop = readId(reader);
        if (!prop) {
            return std::unexpected(prop.error());
        }
        if (*prop == nidEnd) {
            break;
        }

        auto propOffset = reader.offset();
        auto propSize = readNumber(reader);
        if (!propSize) {
            return std::unexpected(propSize.error());
        }
        if (*propSize > reader.remaining()) {
            return fail(ErrorKind::Malformed, "7z file property overruns the header", propOffset);
        }

        switch (*prop) {
        case nidEmptyStream: {
            if (*propSize != (model.files.size() + 7) / 8) {
                return fail(
                    ErrorKind::Malformed,
                    "7z empty-stream bits have the wrong size",
                    propOffset
                );
            }
            auto bits = reader.bytes(checkedCast<std::size_t>(*propSize).value_or(0));
            if (!bits) {
                return std::unexpected(bits.error());
            }
            for (std::size_t index = 0; index < model.files.size(); ++index) {
                bool empty = bitSet(*bits, index);
                model.files[index].hasStream = !empty;
                if (empty) {
                    ++emptyCount;
                }
            }
            break;
        }
        case nidEmptyFile: {
            if (*propSize != (emptyCount + 7) / 8) {
                return fail(
                    ErrorKind::Malformed,
                    "7z empty-file bits have the wrong size",
                    propOffset
                );
            }
            auto bits = reader.bytes(checkedCast<std::size_t>(*propSize).value_or(0));
            if (!bits) {
                return std::unexpected(bits.error());
            }
            std::uint64_t cursor = 0;
            for (auto& meta : model.files) {
                if (meta.hasStream) {
                    continue;
                }
                meta.emptyFile = bitSet(*bits, cursor++);
            }
            break;
        }
        case nidAnti: {
            if (*propSize != (emptyCount + 7) / 8) {
                return fail(ErrorKind::Malformed, "7z anti bits have the wrong size", propOffset);
            }
            auto bits = reader.bytes(checkedCast<std::size_t>(*propSize).value_or(0));
            if (!bits) {
                return std::unexpected(bits.error());
            }
            std::uint64_t cursor = 0;
            for (auto& meta : model.files) {
                if (meta.hasStream) {
                    continue;
                }
                meta.anti = bitSet(*bits, cursor++);
            }
            break;
        }
        case nidStartPos: {
            auto positions = readStartPositions(reader, *numFiles, *propSize, model.files);
            if (!positions) {
                return positions;
            }
            break;
        }
        case nidName: {
            auto names = readNames(reader, *numFiles, *propSize, limits);
            if (!names) {
                return std::unexpected(names.error());
            }
            for (std::size_t index = 0; index < model.files.size(); ++index) {
                model.files[index].name = std::move((*names)[index]);
            }
            break;
        }
        case nidMTime: {
            auto times = readTimes(reader, *numFiles, *propSize, model.files);
            if (!times) {
                return times;
            }
            break;
        }
        case nidCTime:
        case nidATime: {
            std::vector<FileMeta> unused(*numFiles);
            auto times = readTimes(reader, *numFiles, *propSize, unused);
            if (!times) {
                return times;
            }
            break;
        }
        case nidWinAttributes: {
            auto attributes = readAttributes(reader, *numFiles, *propSize, model.files);
            if (!attributes) {
                return attributes;
            }
            break;
        }
        case nidComment:
        case nidDummy: {
            auto skipped = reader.skip(checkedCast<std::size_t>(*propSize).value_or(0));
            if (!skipped) {
                return std::unexpected(skipped.error());
            }
            break;
        }
        default:
            return fail(ErrorKind::Unsupported, "7z file property is not supported", propOffset);
        }
    }
    return {};
}

}
