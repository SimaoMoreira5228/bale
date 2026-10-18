#include "archive/writer.hpp"
#include "cli/archive_commands.hpp"
#include "cli/terminal_text.hpp"

#include <filesystem>
#include <print>
#include <string>
#include <system_error>
#include <utility>

namespace bale::cli {

namespace {

ExitCode writeArchive(
    File file,
    std::string_view archivePath,
    std::string_view directory,
    const CreateOptions& options
) {
    archive::WriterOptions writerOptions;
    writerOptions.chunkSize = options.chunkSize;
    writerOptions.codec = options.codec;
    writerOptions.durable = options.durable;
    auto writer = archive::Writer::create(std::move(file), writerOptions);
    if (!writer) {
        return reportFailure(archivePath, writer.error());
    }

    auto added =
        writer->addTree(std::filesystem::path(directory), std::filesystem::path(archivePath));
    std::string escaped;
    for (const auto& skipped : writer->skipped()) {
        std::println(
            stderr,
            "bale: skipped {}: {}",
            escapeForTerminal(skipped.path, escaped),
            skipped.reason
        );
    }
    if (!added) {
        return reportFailure(directory, added.error());
    }

    auto summary = writer->finish();
    if (!summary) {
        return reportFailure(archivePath, summary.error());
    }

    std::println(
        "created {}: {} entries, {} bytes of content in {} unique of {} chunks, {} bytes total",
        escapeForTerminal(archivePath, escaped),
        summary->entries,
        summary->contentBytes,
        summary->dataRecords,
        summary->chunkReferences,
        summary->archiveSize
    );
    return ExitCode::Ok;
}

}

ExitCode createArchive(
    std::string_view archivePath,
    std::string_view directory,
    const CreateOptions& options
) {
    std::filesystem::path output(archivePath);
    auto file = File::createNew(output);
    if (!file) {
        return reportFailure(archivePath, file.error());
    }

    auto result = writeArchive(std::move(*file), archivePath, directory, options);
    if (result != ExitCode::Ok) {
        std::error_code ignored;
        std::filesystem::remove(output, ignored);
    }
    return result;
}

}
