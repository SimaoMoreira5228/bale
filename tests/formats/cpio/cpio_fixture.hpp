#pragma once

#include "formats/cpio/reader.hpp"
#include "io/temp_file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::cpio::test {

struct EntrySpec {
    std::string name = "file.txt";
    std::string data;
    std::string magic = "070701";
    std::uint64_t ino = 42;
    std::uint32_t mode = 0100644;
    std::uint64_t uid = 1000;
    std::uint64_t gid = 1000;
    std::uint64_t nlink = 1;
    std::uint64_t mtime = 1583298367;
    std::uint32_t check = 0;
};

inline void putHex(std::string& out, std::uint64_t value) {
    constexpr std::string_view digits = "0123456789abcdef";
    for (int shift = 28; shift >= 0; shift -= 4) {
        out.push_back(digits[(value >> shift) & 0xF]);
    }
}

inline std::vector<std::byte> encodeEntry(const EntrySpec& spec) {
    std::string header(spec.magic);
    putHex(header, spec.ino);
    putHex(header, spec.mode);
    putHex(header, spec.uid);
    putHex(header, spec.gid);
    putHex(header, spec.nlink);
    putHex(header, spec.mtime);
    putHex(header, spec.data.size());
    putHex(header, 0);
    putHex(header, 0);
    putHex(header, 0);
    putHex(header, 0);
    putHex(header, spec.name.size() + 1);
    putHex(header, spec.check);

    std::vector<std::byte> bytes;
    for (char value : header) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    for (char value : spec.name) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    bytes.push_back(std::byte{0});
    while (bytes.size() % 4 != 0) {
        bytes.push_back(std::byte{0});
    }
    for (char value : spec.data) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    while (bytes.size() % 4 != 0) {
        bytes.push_back(std::byte{0});
    }
    return bytes;
}

class ArchiveBuilder {
  public:
    ArchiveBuilder& entry(const EntrySpec& spec) {
        auto encoded = encodeEntry(spec);
        bytes_.insert(bytes_.end(), encoded.begin(), encoded.end());
        return *this;
    }

    ArchiveBuilder& trailer() {
        EntrySpec spec;
        spec.name = std::string(trailerName);
        spec.mode = 0;
        spec.ino = 0;
        spec.uid = 0;
        spec.gid = 0;
        spec.mtime = 0;
        return entry(spec);
    }

    ArchiveBuilder& raw(std::string_view text) {
        for (char value : text) {
            bytes_.push_back(static_cast<std::byte>(value));
        }
        return *this;
    }

    ArchiveBuilder& truncate(std::size_t length) {
        if (length < bytes_.size()) {
            bytes_.resize(length);
        }
        return *this;
    }

    [[nodiscard]] const std::vector<std::byte>& bytes() const {
        return bytes_;
    }

  private:
    std::vector<std::byte> bytes_;
};

struct Listed {
    std::string name;
    std::string linkTarget;
    std::uint64_t size = 0;
    EntryKind kind = EntryKind::Regular;
};

struct Listing {
    std::vector<Listed> entries;
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

    for (const auto& entry : reader->entries()) {
        listing.entries.push_back(
            Listed{
                .name = std::string(entry.name),
                .linkTarget = std::string(entry.linkTarget),
                .size = entry.size,
                .kind = entry.kind,
            }
        );
    }
    return listing;
}

}
