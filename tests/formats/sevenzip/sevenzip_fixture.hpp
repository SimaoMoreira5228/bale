#pragma once

#include "checksum/crc.hpp"
#include "codecs/codec_fixture.hpp"
#include "formats/sevenzip/codec_fixture.hpp"
#include "formats/sevenzip/fixture_bytes.hpp"
#include "io/temp_file.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bale::sevenzip::test {

enum class CodecKind : std::uint8_t {
    Copy,
    Lzma1,
    Lzma2,
    Deflate,
    Bzip2,
    Ppmd,
    BcjLzma2,
    AesLzma2,
};

struct EntrySpec {
    std::string name{};
    std::string data{};
    bool dir = false;
    bool emptyFile = false;
    bool anti = false;
    std::int64_t mtime = 1'700'000'000;
    std::uint32_t mode = 0;
};

struct SevenZipSpec {
    std::vector<EntrySpec> entries{};
    CodecKind codec = CodecKind::Lzma2;
    bool solid = true;
    bool compressHeader = true;
    bool encryptHeader = false;
    bool withStartPos = false;
    bool badStartPos = false;
    bool withComment = false;
    bool withCTime = false;
    bool phantomSubstream = false;
};

struct BuiltSevenZip {
    Bytes bytes{};
    std::size_t packStart = 0;
    std::vector<std::size_t> folderPackOffsets{};
    std::vector<std::size_t> folderPackSizes{};
    std::size_t headerStart = 0;
    std::size_t headerSize = 0;
    // NOTE: file offsets below are only valid when compressHeader is false,
    // where the inner header sits in the file unmodified. Zero means absent.
    std::size_t numFilesOffset = 0;
    std::size_t subCountOffset = 0;
    std::vector<std::size_t> subSizeOffsets{};
    std::vector<std::size_t> packCrcOffsets{};
    std::vector<std::size_t> folderCrcOffsets{};
    std::vector<std::size_t> subCrcOffsets{};
    std::size_t firstNameUnitOffset = 0;
    std::size_t innerStart = 0;
};

struct FolderSpec {
    std::vector<std::vector<std::uint8_t>> ids{};
    std::vector<Bytes> props{};
    Bytes packed{};
    Bytes unpacked{};
    std::vector<Bytes> substreams{};
};

inline FolderSpec folderFor(CodecKind codec, std::vector<Bytes> subs) {
    FolderSpec folder;
    folder.substreams = std::move(subs);
    for (const auto& sub : folder.substreams) {
        folder.unpacked.insert(folder.unpacked.end(), sub.begin(), sub.end());
    }
    switch (codec) {
    case CodecKind::Copy:
        folder.ids.push_back({0x00});
        folder.packed = folder.unpacked;
        break;
    case CodecKind::Lzma1: {
        folder.ids.push_back({0x03, 0x01, 0x01});
        Bytes props{
            std::byte{0x5D},
            std::byte{0x00},
            std::byte{0x10},
            std::byte{0x00},
            std::byte{0x00}
        };
        folder.props.push_back(props);
        folder.packed = lzma1Encode(folder.unpacked);
        break;
    }
    case CodecKind::Lzma2: {
        folder.ids.push_back({0x21});
        folder.props.push_back(Bytes{std::byte{0x00}});
        folder.packed = lzma2Encode(folder.unpacked);
        break;
    }
    case CodecKind::Deflate:
        folder.ids.push_back({0x04, 0x01, 0x08});
        folder.packed = bale::test::deflateRaw(folder.unpacked);
        break;
    case CodecKind::Bzip2:
        folder.ids.push_back({0x04, 0x02, 0x02});
        folder.packed = bale::test::bzip2Compress(folder.unpacked);
        break;
    case CodecKind::Ppmd:
        folder.ids.push_back({0x03, 0x04, 0x01});
        folder.props.push_back(
            Bytes{
                std::byte{0x06},
                std::byte{0x00},
                std::byte{0x00},
                std::byte{0x01},
                std::byte{0x00}
            }
        );
        folder.packed = folder.unpacked;
        break;
    case CodecKind::BcjLzma2:
        folder.ids.push_back({0x21});
        folder.ids.push_back({0x03, 0x03, 0x01, 0x03});
        folder.props.push_back(Bytes{std::byte{0x00}});
        folder.packed = lzma2BcjEncode(folder.unpacked);
        break;
    case CodecKind::AesLzma2:
        folder.ids.push_back({0x06, 0xF1, 0x07, 0x01});
        folder.ids.push_back({0x21});
        folder.props.push_back(aesProps());
        folder.props.push_back(Bytes{std::byte{0x00}});
        folder.packed = lzma2Encode(folder.unpacked);
        break;
    }
    return folder;
}

inline std::size_t numberSize(std::uint64_t value) {
    Bytes probe;
    putNumber(probe, value);
    return probe.size();
}

inline std::uint64_t unixToFileTime(std::int64_t unix) {
    return (static_cast<std::uint64_t>(unix) + 11'644'473'600ULL) * 10'000'000ULL;
}

inline BuiltSevenZip buildSevenZip(const SevenZipSpec& spec) {
    BuiltSevenZip built;
    Bytes& out = built.bytes;

    std::vector<FolderSpec> folders;
    std::vector<std::size_t> packCrcRel;
    std::vector<std::size_t> folderCrcRel;
    std::vector<std::size_t> subCrcRel;
    std::vector<std::size_t> subSizeRel;
    std::size_t subCountRel = 0;
    std::size_t firstNameUnitRel = 0;
    std::size_t numFilesRel = 0;
    if (spec.solid) {
        std::vector<Bytes> subs;
        for (const auto& entry : spec.entries) {
            if (entry.dir || entry.emptyFile || entry.anti) {
                continue;
            }
            subs.emplace_back(asBytes(entry.data).begin(), asBytes(entry.data).end());
        }
        if (!subs.empty()) {
            folders.push_back(folderFor(spec.codec, std::move(subs)));
        }
    } else {
        for (const auto& entry : spec.entries) {
            if (entry.dir || entry.emptyFile || entry.anti) {
                continue;
            }
            std::vector<Bytes> subs;
            subs.emplace_back(asBytes(entry.data).begin(), asBytes(entry.data).end());
            folders.push_back(folderFor(spec.codec, std::move(subs)));
        }
    }
    built.packStart = 32;
    std::vector<std::uint64_t> packSizes;
    std::vector<std::uint32_t> packCrcs;
    for (const auto& folder : folders) {
        packSizes.push_back(folder.packed.size());
        packCrcs.push_back(Crc32::of(folder.packed));
    }

    Bytes inner;
    put8(inner, 0x01);
    if (!folders.empty()) {
        put8(inner, 0x04);
        put8(inner, 0x06);
        putNumber(inner, 0);
        putNumber(inner, folders.size());
        put8(inner, 0x09);
        for (auto size : packSizes) {
            putNumber(inner, size);
        }
        put8(inner, 0x0A);
        put8(inner, 0x01);
        for (auto crc : packCrcs) {
            packCrcRel.push_back(inner.size());
            put32(inner, crc);
        }
        put8(inner, 0x00);

        put8(inner, 0x07);
        put8(inner, 0x0B);
        putNumber(inner, folders.size());
        put8(inner, 0x00);
        for (const auto& folder : folders) {
            putNumber(inner, folder.ids.size());
            for (std::size_t index = 0; index < folder.ids.size(); ++index) {
                std::uint8_t flags = static_cast<std::uint8_t>(folder.ids[index].size());
                if (index < folder.props.size() && !folder.props[index].empty()) {
                    flags |= 0x20;
                }
                put8(inner, flags);
                for (std::uint8_t byte : folder.ids[index]) {
                    put8(inner, byte);
                }
                if (index < folder.props.size() && !folder.props[index].empty()) {
                    putNumber(inner, folder.props[index].size());
                    inner.insert(
                        inner.end(),
                        folder.props[index].begin(),
                        folder.props[index].end()
                    );
                }
            }
            if (folder.ids.size() > 1) {
                putNumber(inner, 1);
                putNumber(inner, 0);
            }
        }
        put8(inner, 0x0C);
        for (const auto& folder : folders) {
            if (folder.ids.size() == 1) {
                putNumber(inner, folder.unpacked.size());
            } else {
                putNumber(inner, folder.unpacked.size());
                putNumber(inner, folder.unpacked.size());
            }
        }
        put8(inner, 0x0A);
        put8(inner, 0x01);
        for (const auto& folder : folders) {
            folderCrcRel.push_back(inner.size());
            put32(inner, Crc32::of(folder.unpacked));
        }
        put8(inner, 0x00);

        bool anySolid = false;
        for (const auto& folder : folders) {
            if (folder.substreams.size() > 1) {
                anySolid = true;
            }
        }

        std::vector<std::vector<std::uint64_t>> subSizes;
        std::vector<std::vector<std::uint32_t>> subCrcs;
        for (const auto& folder : folders) {
            subSizes.emplace_back();
            subCrcs.emplace_back();
            for (const auto& sub : folder.substreams) {
                subSizes.back().push_back(sub.size());
                subCrcs.back().push_back(Crc32::of(sub));
            }
        }

        bool wroteSubstreams = false;
        if (anySolid) {
            put8(inner, 0x08);
            wroteSubstreams = true;
            put8(inner, 0x0D);
            subCountRel = inner.size();
            for (std::size_t folder = 0; folder < subSizes.size(); ++folder) {
                std::uint64_t count = subSizes[folder].size();
                if (spec.phantomSubstream && folder == 0) {
                    ++count;
                }
                putNumber(inner, count);
            }
            put8(inner, 0x09);
            for (std::size_t folder = 0; folder < subSizes.size(); ++folder) {
                const auto& sizes = subSizes[folder];
                std::size_t written = sizes.empty() ? 0 : sizes.size() - 1;
                if (spec.phantomSubstream && folder == 0 && !sizes.empty()) {
                    ++written;
                }
                for (std::size_t index = 0; index < written && index < sizes.size(); ++index) {
                    subSizeRel.push_back(inner.size());
                    putNumber(inner, sizes[index]);
                }
            }
        }
        {
            std::uint64_t total = 0;
            for (const auto& sizes : subSizes) {
                total += sizes.size();
            }
            if (total > 0) {
                if (!wroteSubstreams) {
                    put8(inner, 0x08);
                    wroteSubstreams = true;
                }
                put8(inner, 0x0A);
                put8(inner, 0x01);
                for (std::size_t folder = 0; folder < subCrcs.size(); ++folder) {
                    for (auto crc : subCrcs[folder]) {
                        subCrcRel.push_back(inner.size());
                        put32(inner, crc);
                    }
                    if (spec.phantomSubstream && folder == 0) {
                        put32(inner, 0);
                    }
                }
            }
        }
        if (wroteSubstreams) {
            put8(inner, 0x00);
        }
        put8(inner, 0x00);
    }

    put8(inner, 0x05);
    numFilesRel = inner.size();
    putNumber(inner, spec.entries.size());

    std::uint64_t emptyCount = 0;
    for (const auto& entry : spec.entries) {
        if (entry.dir || entry.emptyFile || entry.anti) {
            ++emptyCount;
        }
    }
    if (emptyCount > 0) {
        put8(inner, 0x0E);
        Bytes bits((spec.entries.size() + 7) / 8, std::byte{0});
        for (std::size_t index = 0; index < spec.entries.size(); ++index) {
            const auto& entry = spec.entries[index];
            if (entry.dir || entry.emptyFile || entry.anti) {
                bits[index / 8] |= static_cast<std::byte>(0x80 >> (index % 8));
            }
        }
        putNumber(inner, bits.size());
        inner.insert(inner.end(), bits.begin(), bits.end());

        bool anyEmptyFile = false;
        bool anyAnti = false;
        for (const auto& entry : spec.entries) {
            if (!entry.dir && !entry.emptyFile && !entry.anti) {
                continue;
            }
            if (entry.emptyFile) {
                anyEmptyFile = true;
            }
            if (entry.anti) {
                anyAnti = true;
            }
        }
        if (anyEmptyFile || !spec.entries.empty()) {
            put8(inner, 0x0F);
            Bytes fileBits((emptyCount + 7) / 8, std::byte{0});
            std::uint64_t cursor = 0;
            for (const auto& entry : spec.entries) {
                if (!entry.dir && !entry.emptyFile && !entry.anti) {
                    continue;
                }
                if (entry.emptyFile) {
                    fileBits[cursor / 8] |= static_cast<std::byte>(0x80 >> (cursor % 8));
                }
                ++cursor;
            }
            putNumber(inner, fileBits.size());
            inner.insert(inner.end(), fileBits.begin(), fileBits.end());
        }
        if (anyAnti) {
            put8(inner, 0x10);
            Bytes antiBits((emptyCount + 7) / 8, std::byte{0});
            std::uint64_t cursor = 0;
            for (const auto& entry : spec.entries) {
                if (!entry.dir && !entry.emptyFile && !entry.anti) {
                    continue;
                }
                if (entry.anti) {
                    antiBits[cursor / 8] |= static_cast<std::byte>(0x80 >> (cursor % 8));
                }
                ++cursor;
            }
            putNumber(inner, antiBits.size());
            inner.insert(inner.end(), antiBits.begin(), antiBits.end());
        }
    }

    if (spec.withStartPos || spec.badStartPos) {
        put8(inner, 0x18);
        Bytes positions;
        positions.push_back(std::byte{0x01});
        positions.push_back(std::byte{0x00});
        std::uint64_t solidOffset = 0;
        for (const auto& entry : spec.entries) {
            if (entry.dir || entry.emptyFile || entry.anti) {
                put64(positions, 0);
                continue;
            }
            std::uint64_t value = spec.solid ? solidOffset : 0;
            if (spec.badStartPos) {
                value += 1;
            }
            std::array<std::byte, 8> raw{};
            storeLe(raw.data(), value);
            positions.insert(positions.end(), raw.begin(), raw.end());
            solidOffset += entry.data.size();
        }
        putNumber(inner, positions.size());
        inner.insert(inner.end(), positions.begin(), positions.end());
    }

    {
        put8(inner, 0x11);
        Bytes names;
        names.push_back(std::byte{0x00});
        std::size_t namesPropStart = inner.size();
        std::size_t firstNameRel = 0;
        bool firstName = true;
        for (const auto& entry : spec.entries) {
            if (firstName) {
                firstNameRel = names.size();
                firstName = false;
            }
            putUtf16(names, entry.name);
        }
        firstNameUnitRel = namesPropStart + numberSize(names.size()) + firstNameRel;
        putNumber(inner, names.size());
        inner.insert(inner.end(), names.begin(), names.end());
    }

    {
        put8(inner, 0x14);
        Bytes times;
        times.push_back(std::byte{0x01});
        times.push_back(std::byte{0x00});
        for (const auto& entry : spec.entries) {
            std::array<std::byte, 8> raw{};
            storeLe(raw.data(), unixToFileTime(entry.mtime));
            times.insert(times.end(), raw.begin(), raw.end());
        }
        putNumber(inner, times.size());
        inner.insert(inner.end(), times.begin(), times.end());
    }

    if (spec.withCTime) {
        put8(inner, 0x12);
        Bytes times;
        times.push_back(std::byte{0x01});
        times.push_back(std::byte{0x00});
        for (const auto& entry : spec.entries) {
            std::array<std::byte, 8> raw{};
            storeLe(raw.data(), unixToFileTime(entry.mtime + 100));
            times.insert(times.end(), raw.begin(), raw.end());
        }
        putNumber(inner, times.size());
        inner.insert(inner.end(), times.begin(), times.end());
    }

    {
        put8(inner, 0x15);
        Bytes attrs;
        attrs.push_back(std::byte{0x01});
        attrs.push_back(std::byte{0x00});
        for (const auto& entry : spec.entries) {
            std::uint32_t attributes = 0;
            if (entry.dir) {
                std::uint32_t mode = entry.mode != 0 ? entry.mode : 040755;
                attributes = (mode << 16) | 0x10;
            } else {
                std::uint32_t mode = entry.mode != 0 ? entry.mode : 0100644;
                attributes = (mode << 16) | 0x20;
            }
            std::array<std::byte, 4> raw{};
            storeLe(raw.data(), attributes);
            attrs.insert(attrs.end(), raw.begin(), raw.end());
        }
        putNumber(inner, attrs.size());
        inner.insert(inner.end(), attrs.begin(), attrs.end());
    }

    if (spec.withComment) {
        put8(inner, 0x16);
        putNumber(inner, 5);
        putText(inner, "hello");
    }

    put8(inner, 0x00);
    put8(inner, 0x00);

    Bytes meta;
    Bytes headerPack;
    if (spec.compressHeader) {
        std::vector<std::vector<std::uint8_t>> outerIds{{0x03, 0x01, 0x01}};
        Bytes lzmaProps{
            std::byte{0x5D},
            std::byte{0x00},
            std::byte{0x10},
            std::byte{0x00},
            std::byte{0x00},
        };
        std::vector<Bytes> outerProps{lzmaProps};
        std::vector<std::uint64_t> outerUnpack{inner.size()};
        if (spec.encryptHeader) {
            outerIds = {{0x06, 0xF1, 0x07, 0x01}, {0x03, 0x01, 0x01}};
            outerProps = {aesProps(), lzmaProps};
            headerPack.assign(inner.size(), std::byte{0x5A});
            outerUnpack = {inner.size(), inner.size()};
        } else {
            headerPack = lzma1Encode(inner);
        }

        put8(meta, 0x17);
        put8(meta, 0x06);
        std::uint64_t packPos = 0;
        for (const auto& folder : folders) {
            packPos += folder.packed.size();
        }
        putNumber(meta, packPos);
        putNumber(meta, 1);
        put8(meta, 0x09);
        putNumber(meta, headerPack.size());
        put8(meta, 0x00);
        put8(meta, 0x07);
        put8(meta, 0x0B);
        putNumber(meta, 1);
        put8(meta, 0x00);
        putNumber(meta, outerIds.size());
        for (std::size_t index = 0; index < outerIds.size(); ++index) {
            std::uint8_t flags = static_cast<std::uint8_t>(outerIds[index].size());
            if (index < outerProps.size() && !outerProps[index].empty()) {
                flags |= 0x20;
            }
            put8(meta, flags);
            for (std::uint8_t byte : outerIds[index]) {
                put8(meta, byte);
            }
            if (index < outerProps.size() && !outerProps[index].empty()) {
                putNumber(meta, outerProps[index].size());
                meta.insert(meta.end(), outerProps[index].begin(), outerProps[index].end());
            }
        }
        if (outerIds.size() > 1) {
            putNumber(meta, 1);
            putNumber(meta, 0);
        }
        put8(meta, 0x0C);
        for (auto size : outerUnpack) {
            putNumber(meta, size);
        }
        put8(meta, 0x0A);
        put8(meta, 0x01);
        put32(meta, Crc32::of(inner));
        put8(meta, 0x00);
        put8(meta, 0x00);
    } else {
        meta = inner;
    }

    Bytes body;
    std::vector<std::size_t> relativeOffsets;
    for (const auto& folder : folders) {
        relativeOffsets.push_back(body.size());
        body.insert(body.end(), folder.packed.begin(), folder.packed.end());
    }
    body.insert(body.end(), headerPack.begin(), headerPack.end());
    std::uint64_t nextOffset = body.size();
    body.insert(body.end(), meta.begin(), meta.end());

    built.headerStart = 32 + static_cast<std::size_t>(nextOffset);
    built.headerSize = meta.size();
    built.folderPackOffsets.clear();
    built.folderPackSizes.clear();
    for (std::size_t index = 0; index < folders.size(); ++index) {
        built.folderPackOffsets.push_back(32 + relativeOffsets[index]);
        built.folderPackSizes.push_back(folders[index].packed.size());
    }

    if (!spec.compressHeader) {
        std::size_t base = 32;
        for (const auto& folder : folders) {
            base += folder.packed.size();
        }
        built.innerStart = base;
        built.numFilesOffset = base + numFilesRel;
        if (subCountRel != 0) {
            built.subCountOffset = base + subCountRel;
        }
        for (auto rel : packCrcRel) {
            built.packCrcOffsets.push_back(base + rel);
        }
        for (auto rel : folderCrcRel) {
            built.folderCrcOffsets.push_back(base + rel);
        }
        for (auto rel : subCrcRel) {
            built.subCrcOffsets.push_back(base + rel);
        }
        for (auto rel : subSizeRel) {
            built.subSizeOffsets.push_back(base + rel);
        }
        if (firstNameUnitRel != 0) {
            built.firstNameUnitOffset = base + firstNameUnitRel;
        }
    }

    Bytes signature(32, std::byte{0});
    signature[0] = std::byte{'7'};
    signature[1] = std::byte{'z'};
    signature[2] = std::byte{0xBC};
    signature[3] = std::byte{0xAF};
    signature[4] = std::byte{0x27};
    signature[5] = std::byte{0x1C};
    signature[6] = std::byte{0x00};
    signature[7] = std::byte{0x04};

    storeLe(signature.data() + 12, nextOffset);
    storeLe(signature.data() + 20, static_cast<std::uint64_t>(meta.size()));

    Bytes headerBytes(body.begin() + static_cast<std::ptrdiff_t>(nextOffset), body.end());
    storeLe(signature.data() + 28, Crc32::of(headerBytes));

    Bytes startFields(signature.begin() + 12, signature.begin() + 32);
    storeLe(signature.data() + 8, Crc32::of(startFields));

    out = signature;
    out.insert(out.end(), body.begin(), body.end());
    return built;
}

using bale::test::TempFile;

}
