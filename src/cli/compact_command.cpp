#include "archive/reader.hpp"
#include "archive/writer.hpp"
#include "cli/archive_commands.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"

#include <filesystem>
#include <print>
#include <system_error>
#include <utility>

namespace bale::cli {

ExitCode compactArchive(std::string_view archivePath, std::string_view outputPath, bool durable) {
    auto input = File::openRead(pathFromUtf8(archivePath));
    if (!input) {
        return reportFailure(archivePath, input.error());
    }
    auto reader = archive::Reader::open(std::move(*input));
    if (!reader) {
        return reportFailure(archivePath, reader.error());
    }

    std::filesystem::path output = pathFromUtf8(outputPath);
    auto file = File::createNew(output);
    if (!file) {
        return reportFailure(outputPath, file.error());
    }

    auto summary = archive::Writer::compact(std::move(*file), *reader, durable);
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
