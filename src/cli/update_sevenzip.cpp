#include "cli/archive_commands.hpp"
#include "cli/archive_output.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"
#include "formats/sevenzip/reader.hpp"
#include "formats/sevenzip/writer.hpp"
#include "fswalk/tree_walker.hpp"

#include <algorithm>
#include <filesystem>
#include <print>
#include <random>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bale::cli {

namespace {

OutputOptions sevenZipOutputOptions(const CreateOptions& options) {
    OutputOptions output;
    output.format = OutputFormat::SevenZip;
    output.sevenZipCodec = options.sevenZipCodec;
    output.sevenZipLevel = options.level.value_or(options.sevenZipLevel);
    output.sevenZipSolid = options.sevenZipSolid;
    output.native.durable = options.durable;
    return output;
}

struct FreshEntry {
    std::string path;
    std::string target;
    std::uint64_t size = 0;
    std::optional<std::int64_t> mtimeNanoseconds;
    std::optional<std::uint32_t> mode;
    WalkKind kind = WalkKind::Regular;
};

Result<std::vector<FreshEntry>> collectFreshEntries(TreeWalker& walker) {
    std::vector<FreshEntry> fresh;
    while (true) {
        auto next = walker.next();
        if (!next) {
            return tl::unexpected<Error>(next.error());
        }
        if (*next == nullptr) {
            return fresh;
        }

        const WalkEntry& entry = **next;
        fresh.push_back(
            FreshEntry{
                .path = std::string(entry.path),
                .target = std::string(entry.target),
                .size = entry.size,
                .mtimeNanoseconds = entry.mtimeNanoseconds,
                .mode = entry.mode,
                .kind = entry.kind,
            }
        );
    }
}

Result<void> streamKeptFile(
    ArchiveOutput& output,
    sevenzip::Reader& reader,
    const sevenzip::Entry& entry,
    std::span<std::byte> scratch
) {
    constexpr std::uint32_t fileTypeMask = 0170000;
    constexpr std::uint32_t symlinkType = 0120000;
    constexpr std::uint32_t permissionBits = 07777;
    archive::EntryAttributes attributes{
        .mtimeNanoseconds = entry.mtimeNanoseconds,
        .mode =
            entry.mode ? std::optional<std::uint32_t>(*entry.mode & permissionBits) : std::nullopt,
    };
    if (entry.directory) {
        return output.addDirectory(entry.name, attributes);
    }
    if (entry.mode && (*entry.mode & fileTypeMask) == symlinkType) {
        std::string target;
        auto read = reader.streamEntry(entry, scratch, [&target](std::span<const std::byte> chunk) {
            target.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        if (!read) {
            return read;
        }
        attributes.mode.reset();
        return output.addSymlink(entry.name, target, attributes);
    }

    auto begun = output.beginFile(entry.name, entry.size, attributes);
    if (!begun) {
        return begun;
    }
    auto copied = reader.streamEntry(entry, scratch, [&](std::span<const std::byte> chunk) {
        return output.writeFile(chunk);
    });
    if (!copied) {
        return copied;
    }
    return output.endFile();
}

Result<void>
streamFreshFile(ArchiveOutput& output, const std::filesystem::path& root, const FreshEntry& entry) {
    archive::EntryAttributes attributes{
        .mtimeNanoseconds = entry.mtimeNanoseconds,
        .mode = entry.mode,
    };
    switch (entry.kind) {
    case WalkKind::Directory:
        return output.addDirectory(entry.path, attributes);
    case WalkKind::Symlink:
        return output.addSymlink(entry.path, entry.target, attributes);
    case WalkKind::Regular: {
        auto source = File::openRegularNoFollow(root / pathFromUtf8(entry.path));
        if (!source) {
            return tl::unexpected<Error>(source.error());
        }
        return output.addFile(entry.path, *source, entry.size, attributes);
    }
    case WalkKind::HardLink:
        return fail(ErrorKind::Unsupported, "7z archives cannot store hard links");
    }
    return fail(ErrorKind::Unsupported, "unknown file kind");
}

Result<OutputSummary> rewriteSevenZip(
    File tempFile,
    std::string_view archivePath,
    std::string_view directory,
    const CreateOptions& options,
    std::vector<crypto::SecretBytes> signSeeds
) {
    // NOTE: every handle opened here (the existing archive, the walked
    // sources, the temporary output) dies with this scope: Windows cannot
    // replace a file with open handles, so the rename in the caller happens
    // after this returns.
    WalkOptions walkOptions;
    walkOptions.exclude = pathFromUtf8(archivePath);
    walkOptions.hardLinks = false;
    auto walker = TreeWalker::open(pathFromUtf8(directory), walkOptions);
    if (!walker) {
        return tl::unexpected<Error>(walker.error());
    }
    auto fresh = collectFreshEntries(*walker);
    if (!fresh) {
        return tl::unexpected<Error>(fresh.error());
    }
    reportSkipped(walker->skipped());
    std::filesystem::path rootPath = pathFromUtf8(directory);

    auto existing = File::openRead(pathFromUtf8(archivePath));
    if (!existing) {
        return tl::unexpected<Error>(existing.error());
    }
    auto reader = sevenzip::Reader::open(std::move(*existing));
    if (!reader) {
        return tl::unexpected<Error>(reader.error());
    }

    std::vector<sevenzip::Entry> kept(reader->entries().begin(), reader->entries().end());

    auto output = ArchiveOutput::create(std::move(tempFile), sevenZipOutputOptions(options));
    if (!output) {
        return tl::unexpected<Error>(output.error());
    }
    for (auto& seedBytes : signSeeds) {
        if (auto added = output->addSignSeed(std::move(seedBytes)); !added) {
            return tl::unexpected<Error>(added.error());
        }
    }

    // NOTE: 7z has no appendable generation model, so update rewrites the
    // archive: the merged entry list is sorted with directory files winning
    // name collisions, and pack data streams through once, bounded by the
    // writer's fixed buffers.
    std::vector<const sevenzip::Entry*> keptSorted;
    keptSorted.reserve(kept.size());
    for (const auto& entry : kept) {
        keptSorted.push_back(&entry);
    }
    std::ranges::sort(keptSorted, {}, [](const sevenzip::Entry* entry) {
        return entry->name;
    });
    std::vector<const FreshEntry*> freshSorted;
    freshSorted.reserve(fresh->size());
    for (const auto& entry : *fresh) {
        freshSorted.push_back(&entry);
    }
    std::ranges::sort(freshSorted, {}, [](const FreshEntry* entry) -> std::string_view {
        return entry->path;
    });

    std::vector<std::byte> scratch(std::size_t{256} * 1024);
    std::size_t keptIndex = 0;
    std::size_t freshIndex = 0;
    while (keptIndex < keptSorted.size() || freshIndex < freshSorted.size()) {
        bool takeKept = freshIndex == freshSorted.size();
        if (!takeKept && keptIndex < keptSorted.size()) {
            if (keptSorted[keptIndex]->name == freshSorted[freshIndex]->path) {
                ++keptIndex;
                continue;
            }
            takeKept = keptSorted[keptIndex]->name < freshSorted[freshIndex]->path;
        }
        Result<void> stored;
        if (takeKept) {
            stored = streamKeptFile(*output, *reader, *keptSorted[keptIndex], scratch);
            ++keptIndex;
        } else {
            stored = streamFreshFile(*output, rootPath, *freshSorted[freshIndex]);
            ++freshIndex;
        }
        if (!stored) {
            return tl::unexpected<Error>(stored.error());
        }
    }
    return output->finish();
}

}

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

ExitCode updateSevenZipArchive(
    std::string_view archivePath,
    std::string_view directory,
    const CreateOptions& options,
    std::vector<crypto::SecretBytes> signSeeds
) {
    if (options.level) {
        if (auto problem = checkSevenZipLevel(options.sevenZipCodec, *options.level)) {
            return reportFailure(
                archivePath,
                Error{.kind = ErrorKind::Malformed, .what = *problem}
            );
        }
    }

    std::filesystem::path outputPath = pathFromUtf8(archivePath);
    std::filesystem::path tempPath;
    OutputSummary summary;
    {
        std::random_device seed;
        Result<File> created = fail(ErrorKind::Io, "cannot create a temporary file");
        for (int attempt = 0; attempt < 8; ++attempt) {
            tempPath = outputPath;
            tempPath += ".tmp-" + std::to_string(seed()) + std::to_string(seed());
            created = File::createNew(tempPath);
            if (created) {
                break;
            }
        }
        if (!created) {
            return reportFailure(archivePath, created.error());
        }
        File tempFile = std::move(*created);
        auto rewritten = rewriteSevenZip(
            std::move(tempFile),
            archivePath,
            directory,
            options,
            std::move(signSeeds)
        );
        if (!rewritten) {
            std::error_code ignored;
            std::filesystem::remove(tempPath, ignored);
            return reportFailure(archivePath, rewritten.error());
        }
        summary = *rewritten;
    }

    std::error_code renameError;
#ifdef _WIN32
    // NOTE: Windows rename refuses to overwrite the target, so replace it
    // atomically instead; every handle is already closed above.
    if (MoveFileExW(
            tempPath.c_str(),
            outputPath.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        ) == 0) {
        renameError.assign(static_cast<int>(GetLastError()), std::system_category());
    }
#else
    std::filesystem::rename(tempPath, outputPath, renameError);
#endif
    if (renameError) {
        std::error_code ignored;
        std::filesystem::remove(tempPath, ignored);
        Error failure{.kind = ErrorKind::Io, .what = "cannot replace the archive"};
        failure.systemCode = renameError.value();
        return reportFailure(archivePath, failure);
    }

    std::string escaped;
    std::println(
        "updated {} (7z): {} entries, {} bytes total",
        escapeForTerminal(archivePath, escaped),
        summary.entries,
        summary.archiveSize
    );
    return ExitCode::Ok;
}

}
