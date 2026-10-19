#include "archive/writer.hpp"
#include "cli/archive_commands.hpp"
#include "cli/archive_output.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"
#include "fswalk/tree_walker.hpp"

#include <filesystem>
#include <print>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace bale::cli {

namespace {

void reportSkipped(const std::vector<SkippedPath>& skipped) {
    std::string escaped;
    for (const auto& path : skipped) {
        std::println(
            stderr,
            "bale: skipped {}: {}",
            escapeForTerminal(path.path, escaped),
            path.reason
        );
    }
}

Result<void> addTree(ArchiveOutput& output, TreeWalker& walker) {
    while (true) {
        auto next = walker.next();
        if (!next) {
            return std::unexpected(next.error());
        }
        if (*next == nullptr) {
            return {};
        }

        const WalkEntry& entry = **next;
        archive::EntryAttributes attributes{
            .mtimeNanoseconds = entry.mtimeNanoseconds,
            .mode = entry.mode,
        };
        Result<void> added;
        switch (entry.kind) {
        case WalkKind::Directory:
            added = output.addDirectory(entry.path, attributes);
            break;
        case WalkKind::Regular:
            added = output.addFile(entry.path, *entry.file, entry.size, attributes);
            break;
        case WalkKind::Symlink:
            added = output.addSymlink(entry.path, entry.target, attributes);
            break;
        case WalkKind::HardLink:
            added = output.addHardLink(entry.path, entry.target, attributes);
            break;
        }
        if (!added) {
            return added;
        }
    }
}

ExitCode writeArchive(
    File file,
    std::string_view archivePath,
    std::string_view directory,
    const CreateOptions& options
) {
    OutputOptions outputOptions;
    outputOptions.format = options.format;
    outputOptions.level = options.level;
    outputOptions.native.chunkSize = options.chunkSize;
    outputOptions.native.chunkPolicy = options.chunkPolicy;
    outputOptions.native.cdc = options.cdc;
    outputOptions.native.compression = options.compression;
    outputOptions.native.durable = options.durable;
    outputOptions.native.workers = options.workers;
    auto output = ArchiveOutput::create(std::move(file), outputOptions);
    if (!output) {
        return reportFailure(archivePath, output.error());
    }

    WalkOptions walkOptions;
    walkOptions.limits = outputOptions.native.limits;
    walkOptions.exclude = pathFromUtf8(archivePath);
    walkOptions.hardLinks = output->storesHardLinks();
    auto walker = TreeWalker::open(pathFromUtf8(directory), walkOptions);
    if (!walker) {
        return reportFailure(directory, walker.error());
    }

    auto added = addTree(*output, *walker);
    reportSkipped(walker->skipped());
    if (!added) {
        return reportFailure(directory, added.error());
    }

    auto summary = output->finish();
    if (!summary) {
        return reportFailure(archivePath, summary.error());
    }

    std::string escaped;
    if (summary->native) {
        std::println(
            "created {}: {} entries, {} bytes of content in {} unique of {} chunks, {} bytes total",
            escapeForTerminal(archivePath, escaped),
            summary->native->entries,
            summary->native->contentBytes,
            summary->native->dataRecords,
            summary->native->chunkReferences,
            summary->native->archiveSize
        );
        return ExitCode::Ok;
    }
    std::println(
        "created {} ({}): {} entries, {} bytes total",
        escapeForTerminal(archivePath, escaped),
        name(options.format),
        summary->entries,
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
    writerOptions.chunkPolicy = options.chunkPolicy;
    writerOptions.cdc = options.cdc;
    writerOptions.compression = options.compression;
    writerOptions.durable = options.durable;
    writerOptions.workers = options.workers;
    auto writer = archive::Writer::append(std::move(*file), writerOptions);
    if (!writer) {
        return reportFailure(archivePath, writer.error());
    }

    auto added = writer->addTree(pathFromUtf8(directory), pathFromUtf8(archivePath));
    reportSkipped(writer->skipped());
    if (!added) {
        return reportFailure(directory, added.error());
    }

    auto summary = writer->finish();
    if (!summary) {
        return reportFailure(archivePath, summary.error());
    }

    std::string escaped;
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
