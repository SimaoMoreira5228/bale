#pragma once

#include "formats/rpm/reader.hpp"
#include "io/temp_file.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::rpm::test {

// NOTE: all golden files below were built with rpmbuild from RPM 6.0.2 on
// Fedora using the spec in /tmp/opencode/rpmfix (hello-pkg 1.0, three payload
// entries: greeting.txt, run.sh, link.txt); only the filename records the
// payload compressor. Cross-checked with `rpm -qip` and `rpm2cpio | cpio -t`.

inline std::vector<std::byte> golden(std::string_view name) {
    std::filesystem::path path = std::filesystem::path(FORMAT_GOLDEN_DIR) / "rpm" / "data" / name;
    std::ifstream file(path, std::ios::binary);
    std::vector<std::byte> bytes;
    char chunk[4096];
    while (file) {
        file.read(chunk, sizeof(chunk));
        auto count = file.gcount();
        for (std::streamsize index = 0; index < count; ++index) {
            bytes.push_back(static_cast<std::byte>(chunk[index]));
        }
    }
    return bytes;
}

inline void putBe32(std::vector<std::byte>& out, std::uint32_t value) {
    out.push_back(static_cast<std::byte>(value >> 24));
    out.push_back(static_cast<std::byte>(value >> 16));
    out.push_back(static_cast<std::byte>(value >> 8));
    out.push_back(static_cast<std::byte>(value));
}

struct RawTag {
    std::uint32_t tag = 0;
    TagType type = TagType::String;
    std::vector<std::byte> data;
    std::uint64_t count = 1;
};

inline RawTag stringTag(std::uint32_t tag, std::string_view value) {
    RawTag entry;
    entry.tag = tag;
    entry.type = TagType::String;
    entry.count = 1;
    entry.data.reserve(value.size() + 1);
    for (char unit : value) {
        entry.data.push_back(static_cast<std::byte>(unit));
    }
    entry.data.push_back(std::byte{0});
    return entry;
}

inline std::vector<std::byte> buildRecord(const std::vector<RawTag>& tags, bool pad = true) {
    std::vector<std::byte> out;
    out.insert(out.end(), headerMagic.begin(), headerMagic.end());
    out.push_back(std::byte{headerVersion});
    out.insert(out.end(), 4, std::byte{0});

    std::vector<std::byte> store;
    std::vector<std::byte> index;
    index.reserve(tags.size() * headerIndexSize);
    for (const auto& tag : tags) {
        putBe32(index, tag.tag);
        putBe32(index, static_cast<std::uint32_t>(tag.type));
        putBe32(index, static_cast<std::uint32_t>(store.size()));
        putBe32(index, static_cast<std::uint32_t>(tag.count));
        store.insert(store.end(), tag.data.begin(), tag.data.end());
    }

    putBe32(out, static_cast<std::uint32_t>(tags.size()));
    putBe32(out, static_cast<std::uint32_t>(store.size()));
    out.insert(out.end(), index.begin(), index.end());
    out.insert(out.end(), store.begin(), store.end());
    if (pad) {
        while (out.size() % 8 != 0) {
            out.push_back(std::byte{0});
        }
    }
    return out;
}

inline std::vector<std::byte> buildLead(std::uint8_t major, std::string_view name = "hello-pkg") {
    std::vector<std::byte> out;
    out.insert(out.end(), leadMagic.begin(), leadMagic.end());
    out.push_back(static_cast<std::byte>(major));
    out.push_back(std::byte{0});
    // NOTE: type 0 (binary), archnum 1, osnum 1 (Linux), sigtype 5.
    out.push_back(std::byte{0});
    out.push_back(std::byte{0});
    out.push_back(std::byte{0});
    out.push_back(std::byte{1});
    for (std::size_t index = 0; index < 66; ++index) {
        std::byte unit = index < name.size() ? static_cast<std::byte>(name[index]) : std::byte{0};
        out.push_back(unit);
    }
    out.push_back(std::byte{0});
    out.push_back(std::byte{1});
    out.push_back(std::byte{0});
    out.push_back(std::byte{5});
    out.insert(out.end(), 16, std::byte{0});
    return out;
}

inline std::vector<RawTag> minimalTags(std::string_view compressor = "gzip") {
    return {
        stringTag(tagName, "hello-pkg"),
        stringTag(tagVersion, "1.0"),
        stringTag(tagRelease, "1"),
        stringTag(tagArch, "noarch"),
        stringTag(tagOs, "linux"),
        stringTag(tagPayloadFormat, "cpio"),
        stringTag(tagPayloadCompressor, compressor),
        stringTag(tagPayloadFlags, "9"),
    };
}

inline std::vector<std::byte> buildPackage(
    const std::vector<RawTag>& signature,
    const std::vector<RawTag>& header,
    std::span<const std::byte> payload,
    std::uint8_t major = majorV3,
    bool unpaddedMain = true
) {
    auto bytes = buildLead(major);
    auto signatureRecord = buildRecord(signature);
    bytes.insert(bytes.end(), signatureRecord.begin(), signatureRecord.end());
    auto headerRecord = buildRecord(header, !unpaddedMain);
    bytes.insert(bytes.end(), headerRecord.begin(), headerRecord.end());
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

struct Listing {
    Package package;
    std::vector<std::string> names;
    std::optional<Error> error;
};

inline Listing listArchive(std::span<const std::byte> bytes, const Limits& limits = {}) {
    Listing listing;
    bale::test::TempFile archive(bytes);
    auto file = archive.open();
    if (!file) {
        listing.error = file.error();
        return listing;
    }

    auto reader = Reader::open(std::move(*file), limits);
    if (!reader) {
        listing.error = reader.error();
        return listing;
    }

    listing.package = reader->package();
    for (const auto& entry : reader->entries()) {
        listing.names.emplace_back(entry.name);
    }
    return listing;
}

inline std::vector<std::byte>
payloadSlice(std::span<const std::byte> bytes, std::uint64_t& offset) {
    bale::test::TempFile archive(bytes);
    auto file = archive.open();
    auto reader = Reader::open(std::move(*file));
    const auto& package = reader->package();
    offset = package.payloadOffset;
    return std::vector<std::byte>(
        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
        bytes.begin() + static_cast<std::ptrdiff_t>(offset + package.payloadBytes)
    );
}

}
