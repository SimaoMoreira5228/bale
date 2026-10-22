#pragma once

#include "archive/chunk.hpp"
#include "archive/writer.hpp"
#include "archive/writer_profile.hpp"
#include "base/error.hpp"
#include "cli/archive_output.hpp"
#include "extract/extractor.hpp"
#include "format/record.hpp"
#include "formats/compressed/stream.hpp"
#include "formats/detect.hpp"
#include "formats/tar/source.hpp"
#include "io/file.hpp"
#include "security/archive_path.hpp"

#include <cstdint>
#include <optional>
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

using VerifyKeys = std::vector<std::array<std::byte, 32>>;

[[nodiscard]] Result<void> requireSignatures(const archive::Reader& reader, const VerifyKeys& keys);

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
    std::uint32_t imageIndex = 0;
    std::optional<std::string> keyFile;
    VerifyKeys verifyKeys;
};

[[nodiscard]] ExitCode listArchive(std::string_view argument, const ListOptions& options);

[[nodiscard]] ExitCode testArchive(
    std::string_view argument,
    const std::optional<std::string>& keyFile = std::nullopt,
    const VerifyKeys& verifyKeys = {},
    std::uint32_t imageIndex = 0
);

struct CreateOptions {
    OutputFormat format = OutputFormat::Bale;
    std::optional<int> level;
    std::uint32_t chunkSize = archive::defaultChunkSize;
    archive::ChunkPolicy chunkPolicy = archive::ChunkPolicy::Fixed;
    archive::CdcParams cdc = archive::defaultCdcParams;
    archive::CompressionProfile compression = archive::profileFor(archive::Preset::Balanced);
    bool durable = false;
    std::uint32_t workers = archive::defaultWorkers();
    bool experimentalEncryption = false;
    std::vector<std::array<std::byte, 32>> recipients;
    std::optional<std::string> keyFile;
    std::optional<std::string> signKeyFile;
    std::optional<archive::ParityConfig> parity;
    std::optional<std::uint32_t> parityShardSize;
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

[[nodiscard]] ExitCode compactArchive(
    std::string_view archivePath,
    std::string_view outputPath,
    bool durable,
    bool experimentalEncryption = false,
    const std::optional<std::string>& keyFile = std::nullopt,
    const std::optional<std::string>& signKeyFile = std::nullopt,
    const VerifyKeys& verifyKeys = {}
);

struct ConvertOptions {
    OutputFormat format = OutputFormat::Bale;
    std::optional<int> level;
    std::uint32_t imageIndex = 0;
};

[[nodiscard]] ExitCode
convertArchive(std::string_view input, std::string_view output, const ConvertOptions& options);

[[nodiscard]] ExitCode describeArchive(
    std::string_view argument,
    const std::optional<std::string>& keyFile = std::nullopt,
    const VerifyKeys& verifyKeys = {}
);

[[nodiscard]] ExitCode repairArchive(
    std::string_view archivePath,
    const std::optional<std::string>& keyFile = std::nullopt,
    const VerifyKeys& verifyKeys = {}
);

[[nodiscard]] ExitCode createArchiveFromPath(std::string_view input);

[[nodiscard]] ExitCode extractArchive(
    std::string_view argument,
    std::string_view destination,
    const ExtractPolicy& policy,
    const std::optional<std::string>& keyFile = std::nullopt,
    const VerifyKeys& verifyKeys = {},
    std::uint32_t imageIndex = 0
);

[[nodiscard]] ExitCode extractArchiveHere(
    std::string_view argument,
    const std::optional<std::string>& keyFile = std::nullopt,
    const VerifyKeys& verifyKeys = {}
);
[[nodiscard]] ExitCode extractArchiveToFolder(
    std::string_view argument,
    const std::optional<std::string>& keyFile = std::nullopt,
    const VerifyKeys& verifyKeys = {}
);

}
