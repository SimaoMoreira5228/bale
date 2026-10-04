#include "cli/archive_commands.hpp"
#include "cli/terminal_text.hpp"
#include "formats/tar/reader.hpp"
#include "formats/zip/reader.hpp"
#include "security/archive_path.hpp"

#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace bale::cli {

namespace {

constexpr std::size_t extractChunkSize = std::size_t{256} * 1024;
constexpr std::uint64_t maxSymlinkTargetBytes = 4096;
constexpr std::int64_t nanosecondsPerSecond = 1'000'000'000;

struct Tally {
    std::uint64_t extracted = 0;
    std::uint64_t skipped = 0;
    std::uint64_t failed = 0;
    ExitCode firstFailure = ExitCode::Ok;
};

class Session {
  public:
    Session(Extractor extractor, const ExtractPolicy& policy, PathPolicy pathPolicy) :
        extractor_(std::move(extractor)), limits_(policy.limits), pathPolicy_(pathPolicy),
        scratch_(extractChunkSize) {
    }

    [[nodiscard]] Extractor& extractor() {
        return extractor_;
    }

    [[nodiscard]] std::span<std::byte> scratch() {
        return scratch_;
    }

    [[nodiscard]] Result<ArchivePath> path(std::string_view raw) {
        return normalizeArchivePath(std::as_bytes(std::span(raw)), pathPolicy_, limits_, path_);
    }

    [[nodiscard]] Result<ArchivePath> linkPath(std::string_view raw) {
        return normalizeArchivePath(std::as_bytes(std::span(raw)), pathPolicy_, limits_, link_);
    }

    [[nodiscard]] std::string& linkTarget() {
        return linkTarget_;
    }

    void record(std::string_view name, const Result<EntryResult>& result) {
        if (!result) {
            fail(name, result.error());
            return;
        }
        if (result->outcome == EntryOutcome::Skipped) {
            ++tally_.skipped;
            std::println(
                stderr,
                "bale: skipped {}: {}",
                escapeForTerminal(name, escaped_),
                result->reason
            );
            return;
        }
        ++tally_.extracted;
    }

    void fail(std::string_view name, const Error& error) {
        ++tally_.failed;
        if (tally_.firstFailure == ExitCode::Ok) {
            tally_.firstFailure = exitCodeFor(error.kind);
        }
        reportError(escapeForTerminal(name, escaped_), error);
    }

    [[nodiscard]] ExitCode finish() const {
        std::println(
            "extracted {}, skipped {}, failed {}",
            tally_.extracted,
            tally_.skipped,
            tally_.failed
        );
        return tally_.firstFailure;
    }

  private:
    Extractor extractor_;
    Limits limits_;
    PathPolicy pathPolicy_;
    std::vector<std::byte> scratch_;
    std::string path_;
    std::string link_;
    std::string linkTarget_;
    std::string escaped_;
    Tally tally_;
};

[[nodiscard]] std::optional<std::int64_t>
mtimeNanoseconds(std::int64_t seconds, std::uint32_t nanoseconds) {
    constexpr auto max = std::numeric_limits<std::int64_t>::max();
    constexpr auto min = std::numeric_limits<std::int64_t>::min();
    if (seconds > max / nanosecondsPerSecond || seconds < min / nanosecondsPerSecond) {
        return std::nullopt;
    }

    std::int64_t scaled = seconds * nanosecondsPerSecond;
    if (scaled > max - nanoseconds) {
        return std::nullopt;
    }
    return scaled + nanoseconds;
}

template <typename Stream>
[[nodiscard]] Result<EntryResult> writeFile(
    Session& session,
    const ArchivePath& path,
    const EntryMetadata& metadata,
    Stream&& stream
) {
    auto pending = session.extractor().beginFile(path, metadata);
    if (!pending) {
        return std::unexpected(pending.error());
    }

    auto written = stream([&pending](std::span<const std::byte> chunk) {
        return pending->write(chunk);
    });
    if (!written) {
        return std::unexpected(written.error());
    }
    return pending->commit();
}

[[nodiscard]] Result<EntryResult>
extractTarEntry(Session& session, const tar::Reader& reader, const tar::Entry& entry) {
    auto path = session.path(entry.path);
    if (!path) {
        return std::unexpected(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = mtimeNanoseconds(entry.mtimeSeconds, entry.mtimeNanoseconds),
    };
    switch (entry.kind) {
    case tar::EntryKind::Directory:
        return session.extractor().createDirectory(*path, metadata);
    case tar::EntryKind::Regular:
        return writeFile(session, *path, metadata, [&](auto&& sink) {
            return reader.streamData(entry, session.scratch(), sink);
        });
    case tar::EntryKind::Symlink:
        return session.extractor().createSymlink(*path, entry.linkTarget, metadata);
    case tar::EntryKind::HardLink: {
        auto target = session.linkPath(entry.linkTarget);
        if (!target) {
            return std::unexpected(target.error());
        }
        return session.extractor().createHardLink(*path, *target);
    }
    case tar::EntryKind::CharDevice:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::CharacterDevice);
    case tar::EntryKind::BlockDevice:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::BlockDevice);
    case tar::EntryKind::Fifo:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::Fifo);
    case tar::EntryKind::Other:
        return EntryResult{
            .outcome = EntryOutcome::Skipped,
            .reason = "unknown tar entry type",
        };
    }
    return EntryResult{
        .outcome = EntryOutcome::Skipped,
        .reason = "unknown tar entry type",
    };
}

ExitCode extractTar(std::string_view argument, File file, Session& session) {
    auto reader = tar::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    while (true) {
        auto next = reader->next();
        if (!next) {
            session.fail(argument, next.error());
            return session.finish();
        }

        const tar::Entry* entry = *next;
        if (entry == nullptr) {
            return session.finish();
        }

        auto result = extractTarEntry(session, *reader, *entry);
        session.record(entry->path, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
}

[[nodiscard]] bool isZipSymlink(const zip::Entry& entry) {
    constexpr std::uint16_t fileTypeMask = 0170000;
    constexpr std::uint16_t symlinkType = 0120000;
    return entry.unixMode && (*entry.unixMode & fileTypeMask) == symlinkType;
}

[[nodiscard]] Result<EntryResult>
extractZipEntry(Session& session, zip::Reader& reader, const zip::Entry& entry) {
    // TODO: decode CP437 names when the UTF-8 flag is clear; non-ASCII legacy names are refused
    // as invalid UTF-8 until then.
    auto path = session.path(entry.name);
    if (!path) {
        return std::unexpected(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.unixMode ? std::optional<std::uint32_t>(*entry.unixMode) : std::nullopt,
        .mtimeNanoseconds =
            entry.modifiedUnixTime ? mtimeNanoseconds(*entry.modifiedUnixTime, 0) : std::nullopt,
    };
    if (path->directory) {
        return session.extractor().createDirectory(*path, metadata);
    }

    if (isZipSymlink(entry)) {
        if (entry.uncompressedSize > maxSymlinkTargetBytes) {
            return fail(ErrorKind::LimitExceeded, "symlink target too long");
        }

        std::string& target = session.linkTarget();
        target.clear();
        auto read = reader.streamEntry(entry, session.scratch(), [&target](auto chunk) {
            target.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        if (!read) {
            return std::unexpected(read.error());
        }
        return session.extractor().createSymlink(*path, target, metadata);
    }

    return writeFile(session, *path, metadata, [&](auto&& sink) {
        return reader.streamEntry(entry, session.scratch(), sink);
    });
}

ExitCode extractZip(std::string_view argument, File file, Session& session) {
    auto reader = zip::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    auto cursor = reader->entries();
    zip::Entry entry;
    while (true) {
        auto more = cursor.next(entry);
        if (!more) {
            session.fail(argument, more.error());
            return session.finish();
        }
        if (!*more) {
            return session.finish();
        }

        auto result = extractZipEntry(session, *reader, entry);
        session.record(entry.name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
}

}

ExitCode extractArchive(
    std::string_view argument,
    std::string_view destination,
    const ExtractPolicy& policy
) {
    auto archive = openArchive(argument);
    if (!archive) {
        return reportFailure(argument, archive.error());
    }

    std::error_code ignored;
    std::filesystem::create_directories(std::filesystem::path(destination), ignored);
    auto extractor = Extractor::open(std::filesystem::path(destination), policy);
    if (!extractor) {
        return reportFailure(destination, extractor.error());
    }

    PathPolicy pathPolicy;
    if (archive->format == ArchiveFormat::Zip) {
        pathPolicy.backslash = Backslash::Separator;
        Session session(std::move(*extractor), policy, pathPolicy);
        return extractZip(argument, std::move(archive->file), session);
    }

    Session session(std::move(*extractor), policy, pathPolicy);
    return extractTar(argument, std::move(archive->file), session);
}

}
