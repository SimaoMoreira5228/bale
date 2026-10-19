#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "cli/archive_commands.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"
#include "cli/unlock.hpp"

#include <filesystem>
#include <print>
#include <system_error>
#include <utility>

namespace bale::cli {

ExitCode compactArchive(
    std::string_view archivePath,
    std::string_view outputPath,
    bool durable,
    bool experimentalEncryption,
    const std::optional<std::string>& keyFile
) {
    auto input = File::openRead(pathFromUtf8(archivePath));
    if (!input) {
        return reportFailure(archivePath, input.error());
    }
    auto reader = archive::Reader::open(std::move(*input));
    std::optional<archive::Reader> encrypted;
    if (!reader && reader.error().kind == ErrorKind::PasswordRequired) {
        if (!experimentalEncryption) {
            return reportFailure(
                archivePath,
                Error{.kind = ErrorKind::PasswordRequired, .what = "archive is encrypted"}
            );
        }
        auto unlock = buildUnlock(keyFile, true);
        if (!unlock) {
            return reportFailure(archivePath, unlock.error());
        }
        auto retry = File::openRead(pathFromUtf8(archivePath));
        if (!retry) {
            return reportFailure(archivePath, retry.error());
        }
        auto opened = archive::Reader::openEncrypted(
            std::move(*retry),
            archive::ReaderOptions{},
            std::move(*unlock)
        );
        if (!opened) {
            return reportFailure(archivePath, opened.error());
        }
        encrypted.emplace(std::move(*opened));
    } else if (!reader) {
        return reportFailure(archivePath, reader.error());
    }
    archive::Reader& active = encrypted ? *encrypted : *reader;

    std::filesystem::path output = pathFromUtf8(outputPath);
    auto file = File::createNew(output);
    if (!file) {
        return reportFailure(outputPath, file.error());
    }

    Result<archive::WriteSummary> summary =
        fail(ErrorKind::Malformed, "unreachable compact result");
    if (encrypted) {
        summary = archive::Writer::compactEncrypted(std::move(*file), active, durable);
    } else {
        summary = archive::Writer::compact(std::move(*file), active, durable);
    }
    if (!summary) {
        std::error_code ignored;
        std::filesystem::remove(output, ignored);
        return reportFailure(archivePath, summary.error());
    }
    if (!summary) {
        std::error_code ignored;
        std::filesystem::remove(output, ignored);
        return reportFailure(archivePath, summary.error());
    }

    std::string escapedArchive;
    std::string escapedOutput;
    std::println(
        "compacted {} to {}: {} entries, {} data records, {} bytes",
        escapeForTerminal(archivePath, escapedArchive),
        escapeForTerminal(outputPath, escapedOutput),
        summary->entries,
        summary->dataRecords,
        summary->archiveSize
    );
    return ExitCode::Ok;
}

}
