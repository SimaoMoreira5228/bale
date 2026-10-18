#include "formats/bzip2/stream.hpp"
#include "formats/detect.hpp"
#include "formats/tar/header.hpp"
#include "formats/xz/stream.hpp"
#include "formats/zip/reader.hpp"
#include "fuzz/memory_file.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    auto input = bale::fuzz::bytesOf(data, size);
    if (input.size() >= bale::tar::blockSize) {
        static_cast<void>(bale::tar::looksLikeTar(input.first<bale::tar::blockSize>()));
    }
    static_cast<void>(bale::zip::looksLikeZip(input, input));
    static_cast<void>(bale::xz::looksLikeXz(input));
    static_cast<void>(bale::bzip2::looksLikeBzip2(input));

    auto file = bale::fuzz::memoryFile(input);
    if (!file) {
        return 0;
    }
    auto format = bale::detectFormat(*file);
    if (format) {
        static_cast<void>(bale::name(*format));
    }
    return 0;
}
