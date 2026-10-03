#pragma once

#include "base/endian.hpp"
#include "checksum/crc.hpp"
#include "io/file.hpp"

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

namespace bale::test {

using Bytes = std::vector<std::byte>;

inline void put16(Bytes& out, std::uint16_t value) {
    std::array<std::byte, 2> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

inline void put32(Bytes& out, std::uint32_t value) {
    std::array<std::byte, 4> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

inline void put64(Bytes& out, std::uint64_t value) {
    std::array<std::byte, 8> raw{};
    storeLe(raw.data(), value);
    out.insert(out.end(), raw.begin(), raw.end());
}

inline void putText(Bytes& out, std::string_view text) {
    for (char c : text) {
        out.push_back(static_cast<std::byte>(c));
    }
}

inline void patch16(Bytes& out, std::size_t at, std::uint16_t value) {
    storeLe(out.data() + at, value);
}

inline void patch32(Bytes& out, std::size_t at, std::uint32_t value) {
    storeLe(out.data() + at, value);
}

inline std::span<const std::byte> asBytes(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

struct ZipEntrySpec {
    std::string name{};
    std::string data{};
    std::uint16_t method = 0;
    std::uint16_t flags = 0;
    std::uint16_t madeBy = 0x031E;
    std::uint16_t dosTime = 0x6B2A;
    std::uint16_t dosDate = 0x5B51;
    std::uint32_t externalAttributes = 0100644U << 16;
    std::optional<std::uint32_t> crc{};
    Bytes centralExtra{};
    bool zip64 = false;
};

struct ZipSpec {
    std::vector<ZipEntrySpec> entries{};
    std::string comment{};
    Bytes prefix{};
    std::optional<std::uint16_t> entryCount{};
    std::optional<std::uint32_t> directoryOffset{};
    std::uint16_t disk = 0;
    bool zip64End = false;
};

struct BuiltZip {
    Bytes bytes{};
    std::size_t directoryStart = 0;
    std::size_t endStart = 0;
};

inline BuiltZip buildZip(const ZipSpec& spec) {
    BuiltZip built;
    Bytes& out = built.bytes;
    out = spec.prefix;
    auto base = spec.prefix.size();

    std::vector<std::uint64_t> offsets;
    for (const auto& entry : spec.entries) {
        offsets.push_back(out.size() - base);
        auto crc = entry.crc.value_or(Crc32::of(asBytes(entry.data)));
        bool descriptor = (entry.flags & 0x0008) != 0;
        auto size = static_cast<std::uint32_t>(entry.data.size());

        put32(out, 0x04034b50);
        put16(out, entry.zip64 ? 45 : 20);
        put16(out, entry.flags);
        put16(out, entry.method);
        put16(out, entry.dosTime);
        put16(out, entry.dosDate);
        put32(out, descriptor ? 0 : crc);
        put32(out, descriptor ? 0 : (entry.zip64 ? 0xFFFFFFFF : size));
        put32(out, descriptor ? 0 : (entry.zip64 ? 0xFFFFFFFF : size));
        put16(out, static_cast<std::uint16_t>(entry.name.size()));
        put16(out, entry.zip64 ? 20 : 0);
        putText(out, entry.name);
        if (entry.zip64) {
            put16(out, 0x0001);
            put16(out, 16);
            put64(out, entry.data.size());
            put64(out, entry.data.size());
        }
        putText(out, entry.data);
        if (descriptor) {
            put32(out, 0x08074b50);
            put32(out, crc);
            put32(out, size);
            put32(out, size);
        }
    }

    built.directoryStart = out.size();
    for (std::size_t index = 0; index < spec.entries.size(); ++index) {
        const auto& entry = spec.entries[index];
        auto crc = entry.crc.value_or(Crc32::of(asBytes(entry.data)));
        auto size = static_cast<std::uint32_t>(entry.data.size());

        Bytes extra;
        if (entry.zip64) {
            put16(extra, 0x0001);
            put16(extra, 24);
            put64(extra, entry.data.size());
            put64(extra, entry.data.size());
            put64(extra, offsets[index]);
        }
        extra.insert(extra.end(), entry.centralExtra.begin(), entry.centralExtra.end());

        put32(out, 0x02014b50);
        put16(out, entry.madeBy);
        put16(out, entry.zip64 ? 45 : 20);
        put16(out, entry.flags);
        put16(out, entry.method);
        put16(out, entry.dosTime);
        put16(out, entry.dosDate);
        put32(out, crc);
        put32(out, entry.zip64 ? 0xFFFFFFFF : size);
        put32(out, entry.zip64 ? 0xFFFFFFFF : size);
        put16(out, static_cast<std::uint16_t>(entry.name.size()));
        put16(out, static_cast<std::uint16_t>(extra.size()));
        put16(out, 0);
        put16(out, 0);
        put16(out, 0);
        put32(out, entry.externalAttributes);
        put32(out, entry.zip64 ? 0xFFFFFFFF : static_cast<std::uint32_t>(offsets[index]));
        putText(out, entry.name);
        out.insert(out.end(), extra.begin(), extra.end());
    }

    auto directorySize = out.size() - built.directoryStart;
    auto directoryOffset = built.directoryStart - base;
    auto count = static_cast<std::uint16_t>(spec.entries.size());
    if (spec.zip64End) {
        auto recordOffset = out.size() - base;
        put32(out, 0x06064b50);
        put64(out, 44);
        put16(out, 45);
        put16(out, 45);
        put32(out, 0);
        put32(out, 0);
        put64(out, spec.entries.size());
        put64(out, spec.entries.size());
        put64(out, directorySize);
        put64(out, directoryOffset);

        put32(out, 0x07064b50);
        put32(out, 0);
        put64(out, recordOffset);
        put32(out, 1);
    }

    built.endStart = out.size();
    put32(out, 0x06054b50);
    put16(out, spec.disk);
    put16(out, spec.disk);
    put16(out, spec.zip64End ? 0xFFFF : spec.entryCount.value_or(count));
    put16(out, spec.zip64End ? 0xFFFF : spec.entryCount.value_or(count));
    put32(out, spec.zip64End ? 0xFFFFFFFF : static_cast<std::uint32_t>(directorySize));
    put32(
        out,
        spec.zip64End ? 0xFFFFFFFF
                      : spec.directoryOffset.value_or(static_cast<std::uint32_t>(directoryOffset))
    );
    put16(out, static_cast<std::uint16_t>(spec.comment.size()));
    putText(out, spec.comment);
    return built;
}

class TempFile {
  public:
    explicit TempFile(std::span<const std::byte> contents) {
        std::random_device seed;
        auto name = "bale-zip-test-" + std::to_string(seed()) + std::to_string(seed());
        path_ = std::filesystem::temp_directory_path() / name;

        auto file = File::createNew(path_);
        if (file) {
            ok_ = file->append(contents).has_value();
        }
    }

    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;

    ~TempFile() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    [[nodiscard]] bool ok() const {
        return ok_;
    }

    [[nodiscard]] Result<File> open() const {
        return File::openRead(path_);
    }

  private:
    std::filesystem::path path_;
    bool ok_ = false;
};

}
