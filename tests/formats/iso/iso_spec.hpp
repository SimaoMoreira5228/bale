#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace bale::iso::test {

struct FileSpec {
    std::string path = "hello.txt";
    std::string data;
    std::uint32_t mode = 0100644;
    std::int64_t mtime = 1700000000;
    std::string symlink;
    bool rockRidge = true;
    bool longStamp = false;
    std::string systemExtra;
    int extents = 1;
    bool directory = false;
    std::optional<std::uint32_t> extentLba;
    std::string version = ";1";
};

struct IsoSpec {
    std::vector<FileSpec> files = {FileSpec{}};
    bool joliet = false;
    bool boot = false;
    std::string bootData = "BOOT";
    bool noTerminator = false;
    bool duplicatePvd = false;
    bool udfBridge = false;
};

struct IsoImage {
    std::vector<std::byte> bytes;
    std::unordered_map<std::string, std::size_t> records;
    std::size_t catalogByte = 0;
    std::size_t bootImageByte = 0;
    std::size_t terminatorByte = 0;
    std::size_t jolietRootByte = 0;
};

namespace detail {

inline void put16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>(value & 0xFF));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
}

inline void put16Be(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::byte>(value & 0xFF));
}

inline void put32(std::vector<std::byte>& out, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xFF));
    }
}

inline void putBe32(std::vector<std::byte>& out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xFF));
    }
}

inline void putBoth16(std::vector<std::byte>& out, std::uint16_t value) {
    put16(out, value);
    put16Be(out, value);
}

inline void putBoth32(std::vector<std::byte>& out, std::uint32_t value) {
    put32(out, value);
    putBe32(out, value);
}

inline std::array<std::byte, 7> shortDate(std::int64_t mtime) {
    std::time_t when = static_cast<std::time_t>(mtime);
    std::tm broken{};
#if defined(_WIN32)
    gmtime_s(&broken, &when);
#else
    gmtime_r(&when, &broken);
#endif
    return std::array<std::byte, 7>{
        static_cast<std::byte>(broken.tm_year),
        static_cast<std::byte>(broken.tm_mon + 1),
        static_cast<std::byte>(broken.tm_mday),
        static_cast<std::byte>(broken.tm_hour),
        static_cast<std::byte>(broken.tm_min),
        static_cast<std::byte>(broken.tm_sec),
        std::byte{0},
    };
}

inline std::string upper(std::string_view text) {
    std::string out(text);
    for (char& byte : out) {
        if (byte >= 'a' && byte <= 'z') {
            byte = static_cast<char>(byte - 'a' + 'A');
        }
    }
    return out;
}

inline std::size_t suaSizeOf(const std::vector<std::vector<std::byte>>& blobs) {
    std::size_t total = 0;
    for (const auto& blob : blobs) {
        total += blob.size();
    }
    return total;
}

}

struct Planned {
    const FileSpec* file = nullptr;
    std::string leaf;
    std::uint64_t dataSize = 0;
    std::uint32_t dataLba = 0;
    std::vector<std::uint64_t> pieces;
    std::vector<std::vector<std::byte>> keptSua;
    std::vector<std::vector<std::byte>> overflowSua;
    std::uint32_t overflowLba = 0;
    std::size_t recordLength = 0;
};
struct PlannedDir {
    std::string path;
    std::vector<Planned*> members;
    std::uint32_t lba = 0;
    std::uint64_t size = 0;
};

}
