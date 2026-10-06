#pragma once

#include "base/error.hpp"
#include "extract/extractor.hpp"
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

// NOTE: the gzip FNAME when it is a safe single file name, otherwise the archive's own file name
// without its .gz or .zst suffix (or with .out appended when it has neither).
[[nodiscard]] Result<ArchivePath>
singleFileName(std::string_view archive, const CompressedStream& stream, std::string& out);

struct ListOptions {
    bool detailed = false;
};

[[nodiscard]] ExitCode listArchive(std::string_view argument, const ListOptions& options);

[[nodiscard]] ExitCode testArchive(std::string_view argument);

[[nodiscard]] ExitCode extractArchive(
    std::string_view argument,
    std::string_view destination,
    const ExtractPolicy& policy
);

}
