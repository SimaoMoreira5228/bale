#include "formats/rpm/reader.hpp"

#include "base/checked.hpp"
#include "formats/compressed/stream.hpp"

#include <atomic>
#include <random>
#include <system_error>

namespace bale::rpm {

namespace {

constexpr std::size_t stageChunkSize = std::size_t{64} * 1024;

[[nodiscard]] Result<File> stageFile(std::filesystem::path& path) {
    static std::atomic<std::uint64_t> counter{0};
    std::error_code error;
    auto directory = std::filesystem::temp_directory_path(error);
    if (error) {
        auto failure = fail(ErrorKind::Io, "cannot locate the temporary directory");
        failure.error().systemCode = error.value();
        return std::unexpected(failure.error());
    }

    std::random_device seed;
    for (int attempt = 0; attempt < 100; ++attempt) {
        auto unique = seed() ^ (counter.fetch_add(1) + 0x9E3779B9);
        auto candidate = directory / ("bale-rpm-" + std::to_string(unique));
        auto file = File::createNew(candidate);
        if (file) {
            path = std::move(candidate);
            return file;
        }
        if (file.error().kind != ErrorKind::AlreadyExists) {
            return std::unexpected(file.error());
        }
    }
    return fail(ErrorKind::Io, "cannot stage the rpm payload");
}

[[nodiscard]] Result<void>
copySlice(const File& source, std::uint64_t offset, std::uint64_t bytes, File& target) {
    std::vector<std::byte> chunk(stageChunkSize);
    std::uint64_t position = offset;
    std::uint64_t left = bytes;
    while (left > 0) {
        auto want = static_cast<std::size_t>(std::min<std::uint64_t>(left, chunk.size()));
        auto count = source.readAt(position, std::span(chunk).first(want));
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            return fail(ErrorKind::Truncated, "rpm archive ends inside the payload", position);
        }
        auto appended = target.append(std::span<const std::byte>(chunk.data(), *count));
        if (!appended) {
            return std::unexpected(appended.error());
        }
        position += *count;
        left -= *count;
    }
    return {};
}

[[nodiscard]] Result<void>
decompressInto(CompressedStream& stream, File& target, std::uint64_t at) {
    std::vector<std::byte> chunk(stageChunkSize);
    auto sunk = stream.readAll(chunk, [&](std::span<const std::byte> data) {
        return target.append(data);
    });
    if (!sunk) {
        sunk.error().offset = at;
        return std::unexpected(sunk.error());
    }
    return {};
}

}

Reader::Staged::Staged(Staged&& other) noexcept : path(std::move(other.path)), armed(other.armed) {
    other.armed = false;
}

Reader::Staged& Reader::Staged::operator=(Staged&& other) noexcept {
    if (this != &other) {
        release();
        path = std::move(other.path);
        armed = other.armed;
        other.armed = false;
    }
    return *this;
}

Reader::Staged::~Staged() {
    release();
}

void Reader::Staged::release() {
    if (armed) {
        armed = false;
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
}

Result<Reader> Reader::open(File file, const Limits& limits) {
    auto fileSize = file.size();
    if (!fileSize) {
        return std::unexpected(fileSize.error());
    }

    auto package = parsePackage(file, *fileSize, limits);
    if (!package) {
        return std::unexpected(package.error());
    }

    Staged staged;
    std::filesystem::path stagedPath;
    auto stagedFile = stageFile(stagedPath);
    if (!stagedFile) {
        return std::unexpected(stagedFile.error());
    }
    staged.path = std::move(stagedPath);
    staged.armed = true;
    File payloadFile = std::move(*stagedFile);

    if (package->uncompressed) {
        auto copied = copySlice(file, package->payloadOffset, package->payloadBytes, payloadFile);
        if (!copied) {
            return std::unexpected(copied.error());
        }
    } else {
        Staged compressedStaged;
        std::filesystem::path compressedPath;
        auto compressedHandle = stageFile(compressedPath);
        if (!compressedHandle) {
            return std::unexpected(compressedHandle.error());
        }
        compressedStaged.path = std::move(compressedPath);
        compressedStaged.armed = true;
        File compressedFile = std::move(*compressedHandle);
        auto copied =
            copySlice(file, package->payloadOffset, package->payloadBytes, compressedFile);
        if (!copied) {
            return std::unexpected(copied.error());
        }

        DecompressLimits decompress = limits.decompress;
        auto stream =
            CompressedStream::open(std::move(compressedFile), package->compression, decompress);
        if (!stream) {
            return std::unexpected(stream.error());
        }
        auto expanded = decompressInto(*stream, payloadFile, package->payloadOffset);
        if (!expanded) {
            return std::unexpected(expanded.error());
        }
        compressedStaged.release();
    }

    auto cpio = cpio::Reader::open(std::move(payloadFile), limits.cpio);
    if (!cpio) {
        return std::unexpected(cpio.error());
    }

    Reader reader(std::move(*package), limits);
    reader.payload_ = std::move(staged);
    reader.cpio_.emplace(std::move(*cpio));
    reader.entries_.reserve(reader.cpio_->entryCount());
    std::size_t index = 0;
    for (const auto& payload : reader.cpio_->entries()) {
        reader.entries_.push_back(
            Entry{
                .name = payload.name,
                .linkTarget = payload.linkTarget,
                .size = payload.size,
                .mtimeSeconds = payload.mtimeSeconds,
                .mode = payload.mode,
                .kind = payload.kind,
                .payloadIndex = index,
            }
        );
        ++index;
    }
    return reader;
}

}
