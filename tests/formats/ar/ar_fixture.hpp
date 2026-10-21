#pragma once

#include "formats/ar/reader.hpp"
#include "io/temp_file.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bale::ar::test {

struct MemberSpec {
    std::string nameField = "file.txt/";
    std::string data;
    std::string date = "1583298367";
    std::string uid = "1000";
    std::string gid = "1000";
    std::string mode = "100644";
    std::string size;
    std::string terminator = "`\n";
};

inline std::vector<std::byte> encodeMember(const MemberSpec& spec) {
    std::string header;
    auto put = [&](std::string_view text, std::size_t width) {
        auto start = header.size();
        header.append(text);
        while (header.size() - start < width) {
            header.push_back(' ');
        }
    };

    put(spec.nameField, 16);
    put(spec.date, 12);
    put(spec.uid, 6);
    put(spec.gid, 6);
    put(spec.mode, 8);
    put(spec.size.empty() ? std::to_string(spec.data.size()) : spec.size, 10);
    header.append(spec.terminator);

    std::vector<std::byte> bytes;
    for (char value : header) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    for (char value : spec.data) {
        bytes.push_back(static_cast<std::byte>(value));
    }
    if (spec.data.size() % 2 == 1) {
        bytes.push_back(std::byte{'\n'});
    }
    return bytes;
}

class ArchiveBuilder {
  public:
    ArchiveBuilder() {
        for (char value : magic) {
            bytes_.push_back(static_cast<std::byte>(value));
        }
    }

    ArchiveBuilder& member(const MemberSpec& spec) {
        auto encoded = encodeMember(spec);
        bytes_.insert(bytes_.end(), encoded.begin(), encoded.end());
        return *this;
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
    std::uint64_t size = 0;
    std::uint64_t dataOffset = 0;
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
                .size = entry.size,
                .dataOffset = entry.dataOffset,
            }
        );
    }
    return listing;
}

}
