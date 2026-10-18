#pragma once

#include "archive/chunk.hpp"
#include "base/error.hpp"
#include "extract/extractor.hpp"
#include "format/record.hpp"
#include "formats/compressed/stream.hpp"
#include "formats/detect.hpp"
#include "formats/tar/source.hpp"
#include "io/file.hpp"
#include "security/archive_path.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace bale::cli {

enum class ExitCode : std::uint8_t {
    Ok = 0,
    Usage = 2,
    Unsupported = 3,
    InvalidArchive = 4,
    Integrity = 5,
    PasswordRequired = 6,
    UnsafePath = 7,
    Io = 8,
    LimitExceeded = 9,
    AlreadyExists = 10,
};

[[nodiscard]] ExitCode exitCodeFor(ErrorKind kind);

void reportError(std::string_view context, const Error& error);

ExitCode reportFailure(std::string_view context, const Error& error);

struct OpenedArchive {
    File file;
    ArchiveFormat format;
};

[[nodiscard]] Result<OpenedArchive> openArchive(std::string_view argument);

[[nodiscard]] Result<tar::Source> openTarSource(File file, Compression compression);

[[nodiscard]] Result<ArchivePath>
singleFileName(std::string_view archive, const CompressedStream& stream, std::string& out);

struct ListOptions {
    bool detailed = false;
};

[[nodiscard]] ExitCode listArchive(std::string_view argument, const ListOptions& options);

[[nodiscard]] ExitCode testArchive(std::string_view argument);

struct CreateOptions {
    std::uint32_t chunkSize = archive::defaultChunkSize;
    CodecId codec = CodecId::Raw;
    bool durable = false;
};

[[nodiscard]] ExitCode createArchive(
    std::string_view archivePath,
    std::string_view directory,
    const CreateOptions& options
);

[[nodiscard]] ExitCode updateArchive(
    std::string_view archivePath,
    std::string_view directory,
    const CreateOptions& options
);

[[nodiscard]] ExitCode createArchiveFromPath(std::string_view input);

[[nodiscard]] ExitCode extractArchive(
    std::string_view argument,
    std::string_view destination,
    const ExtractPolicy& policy
);

[[nodiscard]] ExitCode extractArchiveHere(std::string_view argument);
[[nodiscard]] ExitCode extractArchiveToFolder(std::string_view argument);

}
