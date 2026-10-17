#pragma once

#include "base/error.hpp"
#include "io/file.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

#include <sys/mman.h>
#include <unistd.h>

namespace bale::fuzz {

inline std::span<const std::byte> bytesOf(const std::uint8_t* data, std::size_t size) {
    return std::as_bytes(std::span(data, size));
}

inline Result<File> memoryFile(std::span<const std::byte> bytes) {
    static const int descriptor = memfd_create("bale-fuzz", MFD_CLOEXEC);
    if (descriptor < 0 || ftruncate(descriptor, 0) != 0) {
        return fail(ErrorKind::Io, "cannot reset the in-memory fuzz file");
    }

    std::size_t written = 0;
    while (written < bytes.size()) {
        auto count = pwrite(
            descriptor,
            bytes.data() + written,
            bytes.size() - written,
            static_cast<off_t>(written)
        );
        if (count <= 0) {
            return fail(ErrorKind::Io, "cannot write the in-memory fuzz file");
        }
        written += static_cast<std::size_t>(count);
    }
    return File::openRead("/proc/self/fd/" + std::to_string(descriptor));
}

}
