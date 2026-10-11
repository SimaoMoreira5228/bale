#include "archive/writer.hpp"
#include "cli/archive_commands.hpp"
#include "cli/filesystem_path.hpp"
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
    writerOptions.compression = options.compression;
    writerOptions.durable = options.durable;
    auto writer = archive::Writer::create(std::move(file), writerOptions);
    if (!writer) {
        return reportFailure(archivePath, writer.error());
    }

    auto added = writer->addTree(pathFromUtf8(directory), pathFromUtf8(archivePath));
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
    std::filesystem::path output = pathFromUtf8(archivePath);
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

ExitCode updateArchive(
    std::string_view archivePath,
    std::string_view directory,
    const CreateOptions& options
) {
    auto file = File::openAppend(pathFromUtf8(archivePath));
    if (!file) {
        return reportFailure(archivePath, file.error());
    }

    archive::WriterOptions writerOptions;
    writerOptions.chunkSize = options.chunkSize;
    writerOptions.compression = options.compression;
    writerOptions.durable = options.durable;
    auto writer = archive::Writer::append(std::move(*file), writerOptions);
    if (!writer) {
        return reportFailure(archivePath, writer.error());
    }

    auto added = writer->addTree(pathFromUtf8(directory), pathFromUtf8(archivePath));
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
        "updated {}: {} entries, {} bytes of content in {} unique of {} chunks, {} bytes total",
        escapeForTerminal(archivePath, escaped),
        summary->entries,
        summary->contentBytes,
        summary->dataRecords,
        summary->chunkReferences,
        summary->archiveSize
    );
    return ExitCode::Ok;
}

ExitCode createArchiveFromPath(std::string_view input) {
    std::filesystem::path source = pathFromUtf8(input);
    std::error_code error;
    auto status = std::filesystem::symlink_status(source, error);
    if (error) {
        Error failure{.kind = ErrorKind::Io, .what = "cannot inspect path"};
        failure.systemCode = error.value();
        return reportFailure(input, failure);
    }
    if (status.type() == std::filesystem::file_type::symlink) {
        return reportFailure(
            input,
            Error{.kind = ErrorKind::UnsafePath, .what = "source is a symlink"}
        );
    }
    if (status.type() != std::filesystem::file_type::directory &&
        status.type() != std::filesystem::file_type::regular) {
        return reportFailure(
            input,
            Error{
                .kind = ErrorKind::Unsupported,
                .what = "source is not a regular file or directory"
            }
        );
    }

    auto output = source;
    output += pathFromUtf8(".bale");
    auto file = File::createNew(output);
    if (!file) {
        return reportFailure(pathToUtf8(output), file.error());
    }

    auto write = [&]() -> Result<archive::WriteSummary> {
        archive::WriterOptions writerOptions;
        auto writer = archive::Writer::create(std::move(*file), writerOptions);
        if (!writer) {
            return std::unexpected(writer.error());
        }

        Result<void> added;
        if (status.type() == std::filesystem::file_type::directory) {
            added = writer->addTree(source, output);
        } else {
            auto sourceFile = File::openRegularNoFollow(source);
            if (!sourceFile) {
                return std::unexpected(sourceFile.error());
            }
            auto name = pathToUtf8(source.filename());
            added = writer->addFile(name, *sourceFile);
        }
        if (!added) {
            return std::unexpected(added.error());
        }
        return writer->finish();
    }();
    if (!write) {
        std::filesystem::remove(output, error);
        return reportFailure(pathToUtf8(output), write.error());
    }

    std::string escaped;
    std::println("created {}", escapeForTerminal(pathToUtf8(output), escaped));
    return ExitCode::Ok;
}

}
