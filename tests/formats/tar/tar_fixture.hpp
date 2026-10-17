#pragma once

#include "formats/tar/header.hpp"
#include "formats/tar/reader.hpp"
#include "io/file.hpp"
#include "io/temp_file.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::tar::test {

using BlockBytes = std::array<std::byte, blockSize>;

inline constexpr std::string_view ustarMagic{
    "ustar\0"
    "00",
    8
};
inline constexpr std::string_view gnuMagic{"ustar  \0", 8};
inline constexpr std::string_view v7Magic{"\0\0\0\0\0\0\0\0", 8};

struct HeaderSpec {
    std::string name;
    char typeflag = '0';
    std::uint64_t size = 0;
    std::string linkName;
    std::string prefix;
    std::string_view magic = ustarMagic;
    std::uint64_t mtime = 0;
    std::uint64_t uid = 0;
    bool base256Size = false;
};

inline void putText(BlockBytes& block, std::size_t offset, std::string_view text) {
    for (std::size_t index = 0; index < text.size(); ++index) {
        block[offset + index] = static_cast<std::byte>(text[index]);
    }
}

inline void
putOctal(BlockBytes& block, std::size_t offset, std::size_t length, std::uint64_t value) {
    for (std::size_t index = length - 1; index-- > 0;) {
        block[offset + index] = static_cast<std::byte>('0' + (value & 7U));
        value >>= 3;
    }
    block[offset + length - 1] = std::byte{0};
}

inline void
putBase256(BlockBytes& block, std::size_t offset, std::size_t length, std::uint64_t value) {
    for (std::size_t index = length; index-- > 1;) {
        block[offset + index] = static_cast<std::byte>(value & 0xFFU);
        value >>= 8;
    }
    block[offset] = std::byte{0x80};
}

inline void sealChecksum(BlockBytes& block) {
    std::fill_n(block.begin() + 148, 8, std::byte{' '});

    std::uint64_t sum = 0;
    for (auto byte : block) {
        sum += std::to_integer<std::uint8_t>(byte);
    }
    putOctal(block, 148, 7, sum);
}

inline BlockBytes makeHeader(const HeaderSpec& spec) {
    BlockBytes block{};
    putText(block, 0, spec.name);
    putOctal(block, 100, 8, 0644);
    putOctal(block, 108, 8, spec.uid);
    putOctal(block, 116, 8, 0);
    if (spec.base256Size) {
        putBase256(block, 124, 12, spec.size);
    } else {
        putOctal(block, 124, 12, spec.size);
    }
    putOctal(block, 136, 12, spec.mtime);
    block[156] = static_cast<std::byte>(spec.typeflag);
    putText(block, 157, spec.linkName);
    putText(block, 257, spec.magic);
    if (spec.magic != v7Magic) {
        putText(block, 265, "user");
        putText(block, 297, "group");
        putText(block, 345, spec.prefix);
    }
    sealChecksum(block);
    return block;
}

inline std::string paxRecord(std::string_view key, std::string_view value) {
    auto body = key.size() + value.size() + 3;
    auto length = body + 1;
    while (std::to_string(length).size() + body != length) {
        ++length;
    }
    return std::to_string(length) + " " + std::string(key) + "=" + std::string(value) + "\n";
}

class ArchiveBuilder {
  public:
    ArchiveBuilder& block(const BlockBytes& block) {
        bytes_.insert(bytes_.end(), block.begin(), block.end());
        return *this;
    }

    ArchiveBuilder& data(std::string_view data) {
        for (char value : data) {
            bytes_.push_back(static_cast<std::byte>(value));
        }
        bytes_.resize((bytes_.size() + blockSize - 1) / blockSize * blockSize);
        return *this;
    }

    ArchiveBuilder& entry(HeaderSpec spec, std::string_view content) {
        spec.size = content.size();
        block(makeHeader(spec));
        return data(content);
    }

    ArchiveBuilder& meta(char typeflag, std::string_view content) {
        HeaderSpec spec;
        spec.name = typeflag == 'L' || typeflag == 'K' ? "././@LongLink" : "PaxHeader";
        spec.typeflag = typeflag;
        return entry(spec, content);
    }

    ArchiveBuilder& zeros(std::size_t count) {
        bytes_.resize(bytes_.size() + count * blockSize);
        return *this;
    }

    ArchiveBuilder& raw(std::size_t count, std::byte value) {
        bytes_.insert(bytes_.end(), count, value);
        return *this;
    }

    [[nodiscard]] const std::vector<std::byte>& bytes() const {
        return bytes_;
    }

  private:
    std::vector<std::byte> bytes_;
};

struct Listed {
    std::string path;
    std::string linkTarget;
    std::uint64_t size = 0;
    std::uint64_t dataOffset = 0;
    EntryKind kind = EntryKind::Regular;
};

struct Listing {
    std::vector<Listed> entries;
    std::optional<Error> error;
};

inline Listing listSource(Source source, const Limits& limits = {}) {
    Listing listing;
    Reader reader(std::move(source), limits);
    while (true) {
        auto entry = reader.next();
        if (!entry) {
            listing.error = entry.error();
            return listing;
        }
        if (*entry == nullptr) {
            return listing;
        }

        listing.entries.push_back(
            Listed{
                .path = std::string((*entry)->path),
                .linkTarget = std::string((*entry)->linkTarget),
                .size = (*entry)->size,
                .dataOffset = (*entry)->dataOffset,
                .kind = (*entry)->kind,
            }
        );
    }
}

inline Listing listArchive(std::span<const std::byte> bytes, const Limits& limits = {}) {
    Listing listing;
    bale::test::TempFile archive(bytes);
    auto file = archive.open();
    if (!file) {
        listing.error = file.error();
        return listing;
    }

    auto source = Source::open(std::move(*file));
    if (!source) {
        listing.error = source.error();
        return listing;
    }
    return listSource(std::move(*source), limits);
}

}
