#include "formats/sevenzip/header.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "formats/sevenzip/coding.hpp"
#include "io/byte_reader.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace bale::sevenzip {

namespace {

constexpr std::uint8_t majorVersion = 0;

constexpr std::uint8_t coderFlagComplex = 0x10;
constexpr std::uint8_t coderFlagAttributes = 0x20;
constexpr std::uint8_t coderFlagReserved = 0x40;
constexpr std::uint8_t coderFlagAltMethods = 0x80;
constexpr std::uint8_t coderIdSizeMask = 0x0F;

Result<Coder> readCoder(ByteReader& reader, std::uint64_t offset, const Limits& limits) {
    auto flags = readId(reader);
    if (!flags) {
        return std::unexpected(flags.error());
    }
    if ((*flags & (coderFlagReserved | coderFlagAltMethods)) != 0) {
        return fail(ErrorKind::Malformed, "7z coder uses reserved flags", offset);
    }

    std::uint64_t idSize = *flags & coderIdSizeMask;
    if (idSize == 0 || idSize > 15) {
        return fail(ErrorKind::Malformed, "7z coder id has an impossible size", offset);
    }

    auto id = reader.bytes(static_cast<std::size_t>(idSize));
    if (!id) {
        return std::unexpected(id.error());
    }

    Coder coder;
    for (std::byte byte : *id) {
        coder.id.push_back(std::to_integer<std::uint8_t>(byte));
    }

    bool complex = (*flags & coderFlagComplex) != 0;
    if (complex) {
        auto inStreams = readNumber(reader);
        if (!inStreams) {
            return std::unexpected(inStreams.error());
        }
        auto outStreams = readNumber(reader);
        if (!outStreams) {
            return std::unexpected(outStreams.error());
        }
        coder.inStreams = *inStreams;
        coder.outStreams = *outStreams;
    }

    if ((*flags & coderFlagAttributes) != 0) {
        auto propsSize = readNumber(reader);
        if (!propsSize) {
            return std::unexpected(propsSize.error());
        }
        if (*propsSize > limits.maxHeaderBytes || *propsSize > reader.remaining()) {
            return fail(ErrorKind::Malformed, "7z coder properties overrun the header", offset);
        }

        auto props = reader.bytes(checkedCast<std::size_t>(*propsSize).value_or(0));
        if (!props) {
            return std::unexpected(props.error());
        }
        coder.props.assign(props->begin(), props->end());
    }
    return coder;
}

Result<Folder> readFolder(ByteReader& reader, std::uint64_t offset, const Limits& limits) {
    auto numCoders = readNumber(reader);
    if (!numCoders) {
        return std::unexpected(numCoders.error());
    }
    if (*numCoders == 0 || *numCoders > limits.maxEntries) {
        return fail(ErrorKind::Malformed, "7z folder has an impossible coder count", offset);
    }

    Folder folder;
    folder.coders.reserve(checkedCast<std::size_t>(*numCoders).value_or(0));
    for (std::uint64_t index = 0; index < *numCoders; ++index) {
        auto coder = readCoder(reader, offset, limits);
        if (!coder) {
            return std::unexpected(coder.error());
        }

        auto inTotal = checkedAdd(folder.numInStreams, coder->inStreams);
        auto outTotal = checkedAdd(folder.numOutStreams, coder->outStreams);
        if (!inTotal || !outTotal) {
            return fail(ErrorKind::Malformed, "7z folder stream count overflows", offset);
        }
        folder.numInStreams = *inTotal;
        folder.numOutStreams = *outTotal;
        folder.coders.push_back(std::move(*coder));
    }

    if (folder.numOutStreams == 0) {
        return fail(ErrorKind::Malformed, "7z folder has no output streams", offset);
    }

    auto numBinds = folder.numOutStreams - 1;
    if (numBinds > limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "7z bind pair count exceeds limit", offset);
    }
    folder.binds.reserve(checkedCast<std::size_t>(numBinds).value_or(0));
    for (std::uint64_t index = 0; index < numBinds; ++index) {
        auto inIndex = readNumber(reader);
        if (!inIndex) {
            return std::unexpected(inIndex.error());
        }
        auto outIndex = readNumber(reader);
        if (!outIndex) {
            return std::unexpected(outIndex.error());
        }
        if (*inIndex >= folder.numInStreams || *outIndex >= folder.numOutStreams) {
            return fail(ErrorKind::Malformed, "7z bind pair references no stream", offset);
        }
        folder.binds.push_back({.inIndex = *inIndex, .outIndex = *outIndex});
    }

    auto packed =
        folder.numInStreams > numBinds ? folder.numInStreams - numBinds : std::uint64_t{0};
    if (packed == 0) {
        return fail(ErrorKind::Malformed, "7z folder has no packed streams", offset);
    }
    if (packed > limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "7z packed stream count exceeds limit", offset);
    }
    folder.numPackedStreams = packed;

    if (packed > 1) {
        folder.packedStreams.reserve(checkedCast<std::size_t>(packed).value_or(0));
        for (std::uint64_t index = 0; index < packed; ++index) {
            auto stream = readNumber(reader);
            if (!stream) {
                return std::unexpected(stream.error());
            }
            folder.packedStreams.push_back(*stream);
        }
    }

    folder.finalOutStream = folder.numOutStreams;
    for (std::uint64_t out = 0; out < folder.numOutStreams; ++out) {
        bool bound = false;
        for (const auto& bind : folder.binds) {
            if (bind.outIndex == out) {
                bound = true;
                break;
            }
        }
        if (!bound) {
            folder.finalOutStream = out;
            break;
        }
    }
    if (folder.finalOutStream >= folder.numOutStreams) {
        return fail(ErrorKind::Malformed, "7z folder has no output stream", offset);
    }
    return folder;
}

Result<void> readPackInfo(ByteReader& reader, Model& model, const Limits& limits) {
    auto offset = reader.offset();
    auto packPos = readNumber(reader);
    if (!packPos) {
        return std::unexpected(packPos.error());
    }
    model.packPos = *packPos;

    auto numStreams = readNumber(reader);
    if (!numStreams) {
        return std::unexpected(numStreams.error());
    }
    if (*numStreams > limits.maxEntries) {
        return fail(ErrorKind::LimitExceeded, "7z pack stream count exceeds limit", offset);
    }
    model.packs.resize(checkedCast<std::size_t>(*numStreams).value_or(0));

    auto id = readId(reader);
    if (!id) {
        return std::unexpected(id.error());
    }

    if (*id == nidSize) {
        for (auto& pack : model.packs) {
            auto size = readNumber(reader);
            if (!size) {
                return std::unexpected(size.error());
            }
            pack.size = *size;
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id == nidCrc) {
        auto digests = readDigests(reader, *numStreams, limits);
        if (!digests) {
            return std::unexpected(digests.error());
        }
        for (std::size_t index = 0; index < model.packs.size(); ++index) {
            model.packs[index].crc = (*digests)[index];
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id != nidEnd) {
        return fail(ErrorKind::Malformed, "7z pack info does not end cleanly", reader.offset());
    }
    return {};
}

Result<void> readUnpackInfo(ByteReader& reader, Model& model, const Limits& limits) {
    auto checked = expectId(reader, nidFolder, "7z unpack info must start with a folder");
    if (!checked) {
        return checked;
    }

    auto offset = reader.offset();
    auto numFolders = readNumber(reader);
    if (!numFolders) {
        return std::unexpected(numFolders.error());
    }
    if (*numFolders > limits.maxFolders) {
        return fail(ErrorKind::LimitExceeded, "7z folder count exceeds limit", offset);
    }
    model.folders.reserve(checkedCast<std::size_t>(*numFolders).value_or(0));

    auto external = readId(reader);
    if (!external) {
        return std::unexpected(external.error());
    }
    if (*external != 0) {
        return fail(
            ErrorKind::Unsupported,
            "7z folders in an external stream are not supported",
            reader.offset()
        );
    }

    for (std::uint64_t index = 0; index < *numFolders; ++index) {
        auto folder = readFolder(reader, offset, limits);
        if (!folder) {
            return std::unexpected(folder.error());
        }
        model.folders.push_back(std::move(*folder));
    }

    auto sizes = expectId(reader, nidCoderUnpackSize, "7z folders must declare unpack sizes");
    if (!sizes) {
        return sizes;
    }

    for (auto& folder : model.folders) {
        if (folder.numOutStreams > limits.maxEntries) {
            return fail(ErrorKind::LimitExceeded, "7z folder output count exceeds limit", offset);
        }
        folder.unpackSizes.reserve(checkedCast<std::size_t>(folder.numOutStreams).value_or(0));
        for (std::uint64_t index = 0; index < folder.numOutStreams; ++index) {
            auto size = readNumber(reader);
            if (!size) {
                return std::unexpected(size.error());
            }
            folder.unpackSizes.push_back(*size);
        }
    }

    auto id = readId(reader);
    if (!id) {
        return std::unexpected(id.error());
    }
    if (*id == nidCrc) {
        auto digests = readDigests(reader, *numFolders, limits);
        if (!digests) {
            return std::unexpected(digests.error());
        }
        for (std::size_t index = 0; index < model.folders.size(); ++index) {
            model.folders[index].crc = (*digests)[index];
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id != nidEnd) {
        return fail(ErrorKind::Malformed, "7z unpack info does not end cleanly", reader.offset());
    }
    return {};
}

Result<std::vector<std::vector<SubStream>>>
readSubStreams(ByteReader& reader, const Model& model, const Limits& limits) {
    std::vector<std::vector<SubStream>> streams(model.folders.size());
    std::vector<std::uint64_t> counts(model.folders.size(), 1);

    auto id = readId(reader);
    if (!id) {
        return std::unexpected(id.error());
    }

    if (*id == nidNumUnpackStream) {
        for (std::size_t index = 0; index < model.folders.size(); ++index) {
            auto count = readNumber(reader);
            if (!count) {
                return std::unexpected(count.error());
            }
            if (*count == 0 || *count > limits.maxEntries) {
                return fail(
                    ErrorKind::Malformed,
                    "7z folder has an impossible stream count",
                    reader.offset()
                );
            }
            counts[index] = *count;
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    std::uint64_t total = 0;
    for (std::size_t index = 0; index < counts.size(); ++index) {
        auto next = checkedAdd(total, counts[index]);
        if (!next || *next > limits.maxEntries) {
            return fail(ErrorKind::LimitExceeded, "7z stream count exceeds limit", reader.offset());
        }
        total = *next;
        streams[index].resize(checkedCast<std::size_t>(counts[index]).value_or(0));
    }

    if (*id == nidSize) {
        for (std::size_t folder = 0; folder < model.folders.size(); ++folder) {
            auto output = folderOutputSize(model.folders[folder], reader.offset());
            if (!output) {
                return std::unexpected(output.error());
            }
            std::uint64_t folderSize = *output;

            auto& folderStreams = streams[folder];
            std::uint64_t prefix = 0;
            for (std::size_t index = 0; index + 1 < folderStreams.size(); ++index) {
                auto size = readNumber(reader);
                if (!size) {
                    return std::unexpected(size.error());
                }

                auto next = checkedAdd(prefix, *size);
                if (!next) {
                    return fail(
                        ErrorKind::Malformed,
                        "7z substream sizes overflow",
                        reader.offset()
                    );
                }
                prefix = *next;
                folderStreams[index].size = *size;
            }

            if (prefix > folderSize) {
                return fail(
                    ErrorKind::Malformed,
                    "7z substream sizes exceed the folder",
                    reader.offset()
                );
            }
            folderStreams.back().size = folderSize - prefix;
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    } else {
        for (std::size_t folder = 0; folder < model.folders.size(); ++folder) {
            if (streams[folder].size() != 1) {
                return fail(
                    ErrorKind::Malformed,
                    "7z solid folder is missing its substream sizes",
                    reader.offset()
                );
            }
            auto output = folderOutputSize(model.folders[folder], reader.offset());
            if (!output) {
                return std::unexpected(output.error());
            }
            streams[folder].front().size = *output;
        }
    }

    if (*id == nidCrc) {
        auto digests = readDigests(reader, total, limits);
        if (!digests) {
            return std::unexpected(digests.error());
        }

        std::size_t cursor = 0;
        for (auto& folderStreams : streams) {
            for (auto& stream : folderStreams) {
                stream.crc = (*digests)[cursor++];
            }
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id != nidEnd) {
        return fail(
            ErrorKind::Malformed,
            "7z substream info does not end cleanly",
            reader.offset()
        );
    }
    return streams;
}

Result<void> readStreamsInfo(ByteReader& reader, Model& model, const Limits& limits) {
    auto id = readId(reader);
    if (!id) {
        return std::unexpected(id.error());
    }

    if (*id == nidPackInfo) {
        auto packs = readPackInfo(reader, model, limits);
        if (!packs) {
            return packs;
        }
        model.hasStreams = true;

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id == nidUnpackInfo) {
        if (!model.hasStreams) {
            return fail(ErrorKind::Malformed, "7z folders without pack info", reader.offset());
        }
        auto folders = readUnpackInfo(reader, model, limits);
        if (!folders) {
            return folders;
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id == nidSubStreams) {
        auto streams = readSubStreams(reader, model, limits);
        if (!streams) {
            return std::unexpected(streams.error());
        }
        model.substreams = std::move(*streams);

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id != nidEnd) {
        return fail(ErrorKind::Malformed, "7z streams info does not end cleanly", reader.offset());
    }

    if (model.substreams.empty()) {
        model.substreams.resize(model.folders.size());
        for (std::size_t index = 0; index < model.folders.size(); ++index) {
            auto output = folderOutputSize(model.folders[index], reader.offset());
            if (!output) {
                return std::unexpected(output.error());
            }
            model.substreams[index].push_back(
                SubStream{
                    .size = *output,
                    .crc = std::nullopt,
                }
            );
        }
        return {};
    }

    if (model.folders.empty()) {
        return fail(ErrorKind::Malformed, "7z substreams without folders", reader.offset());
    }
    return {};
}

Result<Model> parseStreamsAndFiles(ByteReader& reader, const Limits& limits) {
    Model model;
    auto id = readId(reader);
    if (!id) {
        return std::unexpected(id.error());
    }

    if (*id == nidArchiveProperties) {
        auto skipped = skipProperties(reader, reader.offset());
        if (!skipped) {
            return std::unexpected(skipped.error());
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id == nidAdditionalStreams) {
        auto additional = readStreamsInfo(reader, model, limits);
        if (!additional) {
            return std::unexpected(additional.error());
        }
        if (model.hasStreams) {
            return fail(
                ErrorKind::Unsupported,
                "7z additional streams are not supported",
                reader.offset()
            );
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id == nidMainStreams) {
        Model main;
        auto streams = readStreamsInfo(reader, main, limits);
        if (!streams) {
            return std::unexpected(streams.error());
        }
        model.packPos = main.packPos;
        model.packs = std::move(main.packs);
        model.folders = std::move(main.folders);
        model.substreams = std::move(main.substreams);
        model.hasStreams = main.hasStreams;

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id == nidFilesInfo) {
        auto files = readFilesInfo(reader, model, limits);
        if (!files) {
            return std::unexpected(files.error());
        }

        id = readId(reader);
        if (!id) {
            return std::unexpected(id.error());
        }
    }

    if (*id != nidEnd) {
        return fail(ErrorKind::Malformed, "7z header does not end cleanly", reader.offset());
    }
    if (!reader.empty()) {
        return fail(ErrorKind::Malformed, "7z header has trailing bytes", reader.offset());
    }
    return model;
}

}

Result<Signature> readSignature(const File& file, const Limits& limits) {
    auto size = file.size();
    if (!size) {
        return std::unexpected(size.error());
    }
    if (*size < signatureSize) {
        return fail(ErrorKind::Malformed, "file too small to be a 7z archive");
    }

    std::array<std::byte, signatureSize> signature{};
    auto read = file.readExactAt(0, signature);
    if (!read) {
        return std::unexpected(read.error());
    }

    if (!std::ranges::equal(signatureMagic, std::span(signature).first(signatureMagic.size()))) {
        return fail(ErrorKind::Malformed, "not a 7z archive");
    }
    if (std::to_integer<std::uint8_t>(signature[6]) != majorVersion) {
        return fail(ErrorKind::Unsupported, "unsupported 7z version");
    }

    std::uint32_t wantCrc = loadLe<std::uint32_t>(signature.data() + 8);
    if (Crc32::of(std::span(signature).subspan(12, 20)) != wantCrc) {
        return fail(ErrorKind::Integrity, "7z start header CRC mismatch");
    }

    std::uint64_t headerOffset = loadLe<std::uint64_t>(signature.data() + 12);
    std::uint64_t headerSize = loadLe<std::uint64_t>(signature.data() + 20);
    std::uint32_t headerCrc = loadLe<std::uint32_t>(signature.data() + 28);

    auto dataStart = checkedAdd(std::uint64_t{signatureSize}, headerOffset);
    if (!dataStart) {
        return fail(ErrorKind::Malformed, "7z header offset overflows");
    }
    auto dataEnd = checkedAdd(*dataStart, headerSize);
    if (!dataEnd) {
        return fail(ErrorKind::Malformed, "7z header size overflows");
    }
    if (*dataEnd > *size) {
        return fail(ErrorKind::Truncated, "7z header extends past end of file");
    }
    if (headerSize > limits.maxHeaderBytes) {
        return fail(ErrorKind::LimitExceeded, "7z header exceeds limit");
    }

    std::vector<std::byte> bytes(checkedCast<std::size_t>(headerSize).value_or(0));
    auto headerRead = file.readExactAt(*dataStart, bytes);
    if (!headerRead) {
        return std::unexpected(headerRead.error());
    }
    if (Crc32::of(bytes) != headerCrc) {
        return fail(ErrorKind::Integrity, "7z header CRC mismatch");
    }

    return Signature{
        .headerOffset = *dataStart,
        .headerSize = headerSize,
        .bytes = std::move(bytes)
    };
}

Result<Model>
parseHeader(std::span<const std::byte> bytes, std::uint64_t baseOffset, const Limits& limits) {
    if (bytes.empty()) {
        return fail(ErrorKind::Malformed, "7z header is empty", baseOffset);
    }

    ByteReader reader(bytes, baseOffset);
    auto first = readId(reader);
    if (!first) {
        return std::unexpected(first.error());
    }

    if (*first == nidEncodedHeader) {
        Model outer;
        auto streams = readStreamsInfo(reader, outer, limits);
        if (!streams) {
            return std::unexpected(streams.error());
        }
        if (!reader.empty()) {
            return fail(
                ErrorKind::Malformed,
                "7z encoded header has trailing bytes",
                reader.offset()
            );
        }
        return outer;
    }

    if (*first != nidHeader) {
        return fail(ErrorKind::Malformed, "7z header has no magic", reader.offset());
    }
    return parseStreamsAndFiles(reader, limits);
}

}
