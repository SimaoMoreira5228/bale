#pragma once

// NOTE: minimal in-test WIM writer for edge and refusal cases. Container
// shapes mirror MS-WIM as implemented in src/formats/wim; all payloads are
// literal stored bytes, never fresh compressed output. Provenance: golden
// content checks live in tests/formats/wim/data (see tools/README).

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace bale::wim::test {

struct TestFile {
    std::string path;
    std::vector<std::byte> data;
    std::uint32_t attrs = 0x20;
    std::uint64_t group = 0;
    std::uint32_t reparseTag = 0;
    std::vector<std::byte> reparseData;
    std::vector<std::pair<std::string, std::vector<std::byte>>> extras;
};

struct TestImage {
    std::vector<TestFile> files;
};

struct TestWim {
    std::vector<TestImage> images = {{}};
    std::uint32_t version = 0x10D00;
    std::uint32_t flags = 0;
    std::uint32_t chunkSize = 0;
    std::uint32_t bootIndex = 0;
    bool solid = false;
    std::vector<std::vector<std::byte>> compressedBlobs;
    bool corruptTable = false;
    std::map<std::string, std::string> subdirOverride;
};

[[nodiscard]] std::vector<std::byte> buildWim(const TestWim& spec);

}
