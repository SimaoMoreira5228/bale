#include "archive/reader.hpp"
#include "cli/archive_commands.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"
#include "cli/unlock.hpp"
#include "formats/ar/reader.hpp"
#include "formats/cab/reader.hpp"
#include "formats/compressed/stream.hpp"
#include "formats/cpio/reader.hpp"
#include "formats/iso/reader.hpp"
#include "formats/rpm/reader.hpp"
#include "formats/sevenzip/reader.hpp"
#include "formats/tar/reader.hpp"
#include "formats/wim/reader.hpp"
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
    Session(
        Extractor extractor,
        std::string_view destination,
        const ExtractPolicy& policy,
        PathPolicy pathPolicy
    ) :
        extractor_(std::move(extractor)), destination_(destination), limits_(policy.limits),
        pathPolicy_(pathPolicy), scratch_(extractChunkSize) {
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

    [[nodiscard]] std::string& zipName() {
        return zipName_;
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
        if (repeatsLastFailure(error)) {
            return;
        }
        lastFailure_ = error;

        ++tally_.failed;
        if (tally_.firstFailure == ExitCode::Ok) {
            tally_.firstFailure = exitCodeFor(error.kind);
        }
        reportError(escapeForTerminal(name, escaped_), error);
    }

    [[nodiscard]] ExitCode finish() {
        auto times = extractor_.finish();
        if (!times) {
            fail(destination_, times.error());
        }

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
    std::string_view destination_;
    Limits limits_;
    PathPolicy pathPolicy_;
    std::vector<std::byte> scratch_;
    std::string path_;
    std::string link_;
    std::string linkTarget_;
    std::string zipName_;
    [[nodiscard]] bool repeatsLastFailure(const Error& error) const {
        if (!lastFailure_ || error.offset == Error::noOffset) {
            return false;
        }
        return lastFailure_->kind == error.kind && lastFailure_->offset == error.offset &&
            lastFailure_->what == error.what;
    }

    std::string escaped_;
    Tally tally_;
    std::optional<Error> lastFailure_;
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
        return tl::unexpected<Error>(pending.error());
    }

    auto written = stream([&pending](std::span<const std::byte> chunk) {
        return pending->write(chunk);
    });
    if (!written) {
        return tl::unexpected<Error>(written.error());
    }
    return pending->commit();
}

[[nodiscard]] Result<EntryResult>
extractTarEntry(Session& session, tar::Reader& reader, const tar::Entry& entry) {
    auto path = session.path(entry.path);
    if (!path) {
        return tl::unexpected<Error>(path.error());
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
            return reader.streamData(session.scratch(), sink);
        });
    case tar::EntryKind::Symlink:
        return session.extractor().createSymlink(*path, entry.linkTarget, metadata);
    case tar::EntryKind::HardLink: {
        auto target = session.linkPath(entry.linkTarget);
        if (!target) {
            return tl::unexpected<Error>(target.error());
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

ExitCode extractTar(std::string_view argument, OpenedArchive archive, Session& session) {
    auto source = openTarSource(std::move(archive.file), archive.format.compression);
    if (!source) {
        return reportFailure(argument, source.error());
    }

    tar::Reader reader(std::move(*source));
    while (true) {
        auto next = reader.next();
        if (!next) {
            session.fail(argument, next.error());
            return session.finish();
        }

        const tar::Entry* entry = *next;
        if (entry == nullptr) {
            return session.finish();
        }

        auto result = extractTarEntry(session, reader, *entry);
        session.record(entry->path, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
}

ExitCode extractSingleFile(std::string_view argument, OpenedArchive archive, Session& session) {
    auto stream = CompressedStream::open(std::move(archive.file), archive.format.compression);
    if (!stream) {
        return reportFailure(argument, stream.error());
    }

    std::string normalized;
    auto path = singleFileName(argument, *stream, normalized);
    if (!path) {
        session.fail(argument, path.error());
        return session.finish();
    }

    EntryMetadata metadata;
    const auto* header = stream->gzipHeader();
    if (header != nullptr && header->mtime != 0) {
        metadata.mtimeNanoseconds = mtimeNanoseconds(header->mtime, 0);
    }

    auto result = writeFile(session, *path, metadata, [&](auto&& sink) {
        return stream->readAll(session.scratch(), sink);
    });
    session.record(path->path, result);
    return session.finish();
}

[[nodiscard]] bool isZipSymlink(const zip::Entry& entry) {
    constexpr std::uint16_t fileTypeMask = 0170000;
    constexpr std::uint16_t symlinkType = 0120000;
    return entry.unixMode && (*entry.unixMode & fileTypeMask) == symlinkType;
}

[[nodiscard]] Result<EntryResult> extractZipEntry(
    Session& session,
    zip::Reader& reader,
    const zip::Entry& entry,
    std::string_view name
) {
    auto path = session.path(name);
    if (!path) {
        return tl::unexpected<Error>(path.error());
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
            return tl::unexpected<Error>(read.error());
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

        auto name = zip::nameAsUtf8(entry, session.zipName());
        if (!name) {
            session.fail(argument, name.error());
            continue;
        }
        auto result = extractZipEntry(session, *reader, entry, *name);
        session.record(*name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
}

[[nodiscard]] bool isSevenZipSymlink(const sevenzip::Entry& entry) {
    constexpr std::uint32_t fileTypeMask = 0170000;
    constexpr std::uint32_t symlinkType = 0120000;
    return entry.mode && (*entry.mode & fileTypeMask) == symlinkType;
}

[[nodiscard]] Result<EntryResult>
extractSevenZipEntry(Session& session, sevenzip::Reader& reader, const sevenzip::Entry& entry) {
    auto path = session.path(entry.name);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = entry.mtimeNanoseconds,
    };
    if (path->directory || entry.directory) {
        return session.extractor().createDirectory(*path, metadata);
    }

    if (isSevenZipSymlink(entry)) {
        if (entry.size > maxSymlinkTargetBytes) {
            return fail(ErrorKind::LimitExceeded, "symlink target too long");
        }

        std::string& target = session.linkTarget();
        target.clear();
        auto read = reader.streamEntry(entry, session.scratch(), [&target](auto chunk) {
            target.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        return session.extractor().createSymlink(*path, target, metadata);
    }

    return writeFile(session, *path, metadata, [&](auto&& sink) {
        return reader.streamEntry(entry, session.scratch(), sink);
    });
}

ExitCode extractSevenZip(std::string_view argument, File file, Session& session) {
    auto reader = sevenzip::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    for (const auto& entry : reader->entries()) {
        auto result = extractSevenZipEntry(session, *reader, entry);
        session.record(entry.name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
    return session.finish();
}

[[nodiscard]] Result<EntryResult>
extractArEntry(Session& session, ar::Reader& reader, const ar::Entry& entry) {
    auto path = session.path(entry.name);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = mtimeNanoseconds(entry.mtimeSeconds, 0),
    };
    return writeFile(session, *path, metadata, [&](auto&& sink) {
        return reader.streamEntry(entry, session.scratch(), sink);
    });
}

ExitCode extractAr(std::string_view argument, File file, Session& session) {
    auto reader = ar::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    for (const auto& entry : reader->entries()) {
        auto result = extractArEntry(session, *reader, entry);
        session.record(entry.name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
    return session.finish();
}

[[nodiscard]] Result<EntryResult>
extractCpioEntry(Session& session, cpio::Reader& reader, const cpio::Entry& entry) {
    auto path = session.path(entry.name);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = mtimeNanoseconds(entry.mtimeSeconds, 0),
    };
    switch (entry.kind) {
    case cpio::EntryKind::Directory:
        return session.extractor().createDirectory(*path, metadata);
    case cpio::EntryKind::Regular:
        return writeFile(session, *path, metadata, [&](auto&& sink) {
            return reader.streamEntry(entry, session.scratch(), sink);
        });
    case cpio::EntryKind::Symlink: {
        if (entry.size > maxSymlinkTargetBytes) {
            return fail(ErrorKind::LimitExceeded, "symlink target too long");
        }

        std::string& target = session.linkTarget();
        target.clear();
        auto read = reader.streamEntry(entry, session.scratch(), [&target](auto chunk) {
            target.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        return session.extractor().createSymlink(*path, target, metadata);
    }
    case cpio::EntryKind::HardLink: {
        auto target = session.linkPath(entry.linkTarget);
        if (!target) {
            return tl::unexpected<Error>(target.error());
        }
        return session.extractor().createHardLink(*path, *target);
    }
    case cpio::EntryKind::CharDevice:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::CharacterDevice);
    case cpio::EntryKind::BlockDevice:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::BlockDevice);
    case cpio::EntryKind::Fifo:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::Fifo);
    case cpio::EntryKind::Socket:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::Socket);
    case cpio::EntryKind::Other:
        return EntryResult{
            .outcome = EntryOutcome::Skipped,
            .reason = "unknown cpio entry type",
        };
    }
    return EntryResult{
        .outcome = EntryOutcome::Skipped,
        .reason = "unknown cpio entry type",
    };
}
ExitCode extractCpio(std::string_view argument, File file, Session& session) {
    auto reader = cpio::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    // NOTE: cpio stores hardlink data with the last link, so earlier links
    // point at files that do not exist yet; create those links last.
    std::vector<const cpio::Entry*> deferred;
    for (const auto& entry : reader->entries()) {
        if (entry.kind == cpio::EntryKind::HardLink) {
            deferred.push_back(&entry);
            continue;
        }

        auto result = extractCpioEntry(session, *reader, entry);
        session.record(entry.name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }

    for (const auto* entry : deferred) {
        auto result = extractCpioEntry(session, *reader, *entry);
        session.record(entry->name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
    return session.finish();
}

[[nodiscard]] Result<EntryResult>
extractRpmEntry(Session& session, rpm::Reader& reader, const rpm::Entry& entry) {
    auto path = session.path(entry.name);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = mtimeNanoseconds(entry.mtimeSeconds, 0),
    };
    switch (entry.kind) {
    case rpm::EntryKind::Directory:
        return session.extractor().createDirectory(*path, metadata);
    case rpm::EntryKind::Regular:
        return writeFile(session, *path, metadata, [&](auto&& sink) {
            return reader.streamEntry(entry, session.scratch(), sink);
        });
    case rpm::EntryKind::Symlink: {
        if (entry.size > maxSymlinkTargetBytes) {
            return fail(ErrorKind::LimitExceeded, "symlink target too long");
        }

        std::string& target = session.linkTarget();
        target.clear();
        auto read = reader.streamEntry(entry, session.scratch(), [&target](auto chunk) {
            target.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        return session.extractor().createSymlink(*path, target, metadata);
    }
    case rpm::EntryKind::HardLink: {
        auto target = session.linkPath(entry.linkTarget);
        if (!target) {
            return tl::unexpected<Error>(target.error());
        }
        return session.extractor().createHardLink(*path, *target);
    }
    case rpm::EntryKind::CharDevice:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::CharacterDevice);
    case rpm::EntryKind::BlockDevice:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::BlockDevice);
    case rpm::EntryKind::Fifo:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::Fifo);
    case rpm::EntryKind::Socket:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::Socket);
    case rpm::EntryKind::Other:
        return EntryResult{
            .outcome = EntryOutcome::Skipped,
            .reason = "unknown rpm entry type",
        };
    }
    return EntryResult{
        .outcome = EntryOutcome::Skipped,
        .reason = "unknown rpm entry type",
    };
}

ExitCode extractRpm(std::string_view argument, File file, Session& session) {
    auto reader = rpm::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    // NOTE: rpm payloads are cpio archives, so hardlink data lives with the
    // last link; create those links after every other entry, like cpio links.
    std::vector<const rpm::Entry*> deferred;
    for (const auto& entry : reader->entries()) {
        if (entry.kind == rpm::EntryKind::HardLink) {
            deferred.push_back(&entry);
            continue;
        }

        auto result = extractRpmEntry(session, *reader, entry);
        session.record(entry.name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }

    for (const auto* entry : deferred) {
        auto result = extractRpmEntry(session, *reader, *entry);
        session.record(entry->name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
    return session.finish();
}

[[nodiscard]] Result<EntryResult>
extractIsoEntry(Session& session, iso::Reader& reader, const iso::Entry& entry) {
    auto path = session.path(entry.name);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = mtimeNanoseconds(entry.mtimeSeconds, 0),
    };
    switch (entry.kind) {
    case iso::EntryKind::Directory:
        return session.extractor().createDirectory(*path, metadata);
    case iso::EntryKind::Regular:
        return writeFile(session, *path, metadata, [&](auto&& sink) {
            return reader.streamEntry(entry, session.scratch(), sink);
        });
    case iso::EntryKind::Symlink:
        return session.extractor().createSymlink(*path, entry.linkTarget, metadata);
    case iso::EntryKind::CharDevice:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::CharacterDevice);
    case iso::EntryKind::BlockDevice:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::BlockDevice);
    case iso::EntryKind::Fifo:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::Fifo);
    case iso::EntryKind::Socket:
        return session.extractor().skipOrRefuseSpecialFile(*path, SpecialFileKind::Socket);
    case iso::EntryKind::Other:
        return EntryResult{
            .outcome = EntryOutcome::Skipped,
            .reason = "unknown iso entry type",
        };
    }
    return EntryResult{
        .outcome = EntryOutcome::Skipped,
        .reason = "unknown iso entry type",
    };
}

ExitCode extractIso(std::string_view argument, File file, Session& session) {
    auto reader = iso::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    for (const auto& entry : reader->entries()) {
        auto result = extractIsoEntry(session, *reader, entry);
        session.record(entry.name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
    return session.finish();
}

[[nodiscard]] Result<EntryResult>
extractCabEntry(Session& session, cab::Reader& reader, const cab::Entry& entry) {
    auto path = session.path(entry.name);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = mtimeNanoseconds(entry.mtimeSeconds, 0),
    };
    if (path->directory || entry.directory) {
        return session.extractor().createDirectory(*path, metadata);
    }
    return writeFile(session, *path, metadata, [&](auto&& sink) {
        return reader.streamEntry(entry, session.scratch(), sink);
    });
}

ExitCode extractCab(std::string_view argument, File file, Session& session) {
    auto reader = cab::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    for (const auto& entry : reader->entries()) {
        auto result = extractCabEntry(session, *reader, entry);
        session.record(entry.name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
    return session.finish();
}

[[nodiscard]] Result<EntryResult>
extractWimEntry(Session& session, wim::Reader& reader, const wim::Entry& entry) {
    auto path = session.path(entry.name);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = mtimeNanoseconds(entry.mtimeSeconds, 0),
    };
    switch (entry.kind) {
    case wim::EntryKind::Directory:
        return session.extractor().createDirectory(*path, metadata);
    case wim::EntryKind::Regular:
    case wim::EntryKind::AlternateStream:
        if (entry.kind == wim::EntryKind::AlternateStream) {
            return EntryResult{
                .outcome = EntryOutcome::Skipped,
                .reason = "alternate data stream (only the default stream is extracted)",
            };
        }
        return writeFile(session, *path, metadata, [&](auto&& sink) {
            return reader.streamEntry(entry, session.scratch(), sink);
        });
    case wim::EntryKind::Symlink:
        if (entry.linkTarget.empty()) {
            return EntryResult{
                .outcome = EntryOutcome::Skipped,
                .reason = "symlink without a target",
            };
        }
        return session.extractor().createSymlink(*path, entry.linkTarget, metadata);
    case wim::EntryKind::HardLink: {
        auto target = session.linkPath(entry.linkTarget);
        if (!target) {
            return tl::unexpected<Error>(target.error());
        }
        return session.extractor().createHardLink(*path, *target);
    }
    case wim::EntryKind::Other:
        return EntryResult{
            .outcome = EntryOutcome::Skipped,
            .reason = "special or unsupported WIM entry",
        };
    }
    return EntryResult{
        .outcome = EntryOutcome::Skipped,
        .reason = "special or unsupported WIM entry",
    };
}

ExitCode
extractWim(std::string_view argument, File file, Session& session, std::uint32_t imageIndex) {
    auto reader = wim::Reader::open(std::move(file), {}, imageIndex);
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    // NOTE: WIM hard links can point either way in archive order, so links
    // are created after every other entry, like cpio links.
    std::vector<const wim::Entry*> deferred;
    for (const auto& entry : reader->entries()) {
        if (entry.kind == wim::EntryKind::HardLink) {
            deferred.push_back(&entry);
            continue;
        }

        auto result = extractWimEntry(session, *reader, entry);
        session.record(entry.name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }

    for (const auto* entry : deferred) {
        auto result = extractWimEntry(session, *reader, *entry);
        session.record(entry->name, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            return session.finish();
        }
    }
    return session.finish();
}

[[nodiscard]] Result<EntryResult>
extractBaleEntry(Session& session, archive::Reader& reader, const archive::ManifestEntry& entry) {
    auto path = session.path(entry.path);
    if (!path) {
        return tl::unexpected<Error>(path.error());
    }

    EntryMetadata metadata{
        .mode = entry.mode,
        .mtimeNanoseconds = entry.mtimeNanoseconds,
    };
    switch (entry.kind) {
    case archive::EntryKind::Directory:
        return session.extractor().createDirectory(*path, metadata);
    case archive::EntryKind::Regular:
        return writeFile(session, *path, metadata, [&](auto&& sink) {
            return reader.streamFile(entry, sink);
        });
    case archive::EntryKind::Symlink:
        return session.extractor().createSymlink(*path, entry.target, metadata);
    case archive::EntryKind::HardLink: {
        auto target = session.linkPath(entry.target);
        if (!target) {
            return tl::unexpected<Error>(target.error());
        }
        return session.extractor().createHardLink(*path, *target);
    }
    }
    return EntryResult{
        .outcome = EntryOutcome::Skipped,
        .reason = "unknown bale entry kind",
    };
}

ExitCode extractBale(
    std::string_view argument,
    File file,
    Session& session,
    const std::optional<std::string>& keyFile,
    const VerifyKeys& verifyKeys
) {
    auto reader = archive::Reader::open(std::move(file));
    std::optional<archive::Reader> encrypted;
    if (!reader && reader.error().kind == ErrorKind::PasswordRequired) {
        auto unlock = buildUnlock(keyFile, true);
        if (!unlock) {
            return reportFailure(argument, unlock.error());
        }
        auto retry = File::openRead(pathFromUtf8(argument));
        if (!retry) {
            return reportFailure(argument, retry.error());
        }
        auto opened = archive::Reader::openEncrypted(
            std::move(*retry),
            archive::ReaderOptions{},
            std::move(*unlock)
        );
        if (!opened) {
            return reportFailure(argument, opened.error());
        }
        encrypted.emplace(std::move(*opened));
    } else if (!reader) {
        return reportFailure(argument, reader.error());
    }
    archive::Reader& active = encrypted ? *encrypted : *reader;

    if (auto signed_ = requireSignatures(active, verifyKeys); !signed_) {
        session.fail(argument, signed_.error());
        return session.finish();
    }

    for (const auto& entry : active.manifest().entries) {
        auto result = extractBaleEntry(session, active, entry);
        session.record(entry.path, result);
        if (!result && result.error().kind == ErrorKind::LimitExceeded) {
            break;
        }
    }
    return session.finish();
}

}

ExitCode extractArchive(
    std::string_view argument,
    std::string_view destination,
    const ExtractPolicy& policy,
    const std::optional<std::string>& keyFile,
    const VerifyKeys& verifyKeys,
    std::uint32_t imageIndex
) {
    auto archive = openArchive(argument);
    if (!archive) {
        return reportFailure(argument, archive.error());
    }
    if (archive->format.container != Container::Bale && !verifyKeys.empty()) {
        return reportFailure(
            argument,
            Error{
                .kind = ErrorKind::Malformed,
                .what = "--verify-key applies only to bale archives"
            }
        );
    }
    if (archive->format.container != Container::Wim && imageIndex != 0) {
        return reportFailure(
            argument,
            Error{.kind = ErrorKind::Malformed, .what = "--image applies only to wim archives"}
        );
    }

    std::error_code ignored;
    auto output = pathFromUtf8(destination);
    std::filesystem::create_directories(output, ignored);
    auto extractor = Extractor::open(output, policy);
    if (!extractor) {
        return reportFailure(destination, extractor.error());
    }

    PathPolicy pathPolicy;
    if (archive->format.container == Container::Bale) {
        Session session(std::move(*extractor), destination, policy, pathPolicy);
        return extractBale(argument, std::move(archive->file), session, keyFile, verifyKeys);
    }
    if (archive->format.container == Container::Zip) {
        pathPolicy.backslash = Backslash::Separator;
        Session session(std::move(*extractor), destination, policy, pathPolicy);
        return extractZip(argument, std::move(archive->file), session);
    }
    if (archive->format.container == Container::SevenZip) {
        pathPolicy.backslash = Backslash::Separator;
        Session session(std::move(*extractor), destination, policy, pathPolicy);
        return extractSevenZip(argument, std::move(archive->file), session);
    }
    if (archive->format.container == Container::Cab) {
        pathPolicy.backslash = Backslash::Separator;
        Session session(std::move(*extractor), destination, policy, pathPolicy);
        return extractCab(argument, std::move(archive->file), session);
    }
    if (archive->format.container == Container::Wim) {
        pathPolicy.backslash = Backslash::Separator;
        Session session(std::move(*extractor), destination, policy, pathPolicy);
        return extractWim(argument, std::move(archive->file), session, imageIndex);
    }

    Session session(std::move(*extractor), destination, policy, pathPolicy);
    if (archive->format.container == Container::SingleFile) {
        return extractSingleFile(argument, std::move(*archive), session);
    }
    if (archive->format.container == Container::Tar) {
        return extractTar(argument, std::move(*archive), session);
    }
    if (archive->format.container == Container::Ar) {
        return extractAr(argument, std::move(archive->file), session);
    }
    if (archive->format.container == Container::Cpio) {
        return extractCpio(argument, std::move(archive->file), session);
    }
    if (archive->format.container == Container::Rpm) {
        return extractRpm(argument, std::move(archive->file), session);
    }
    if (archive->format.container == Container::Iso) {
        return extractIso(argument, std::move(archive->file), session);
    }
    return reportFailure(
        argument,
        Error{.kind = ErrorKind::Unsupported, .what = "unrecognized archive format"}
    );
}

ExitCode extractArchiveHere(
    std::string_view argument,
    const std::optional<std::string>& keyFile,
    const VerifyKeys& verifyKeys
) {
    auto archive = pathFromUtf8(argument);
    auto destination = archive.parent_path();
    if (destination.empty()) {
        std::error_code error;
        destination = std::filesystem::current_path(error);
        if (error) {
            Error failure{.kind = ErrorKind::Io, .what = "cannot get current directory"};
            failure.systemCode = error.value();
            return reportFailure(argument, failure);
        }
    }
    return extractArchive(argument, pathToUtf8(destination), {}, keyFile, verifyKeys);
}

ExitCode extractArchiveToFolder(
    std::string_view argument,
    const std::optional<std::string>& keyFile,
    const VerifyKeys& verifyKeys
) {
    auto archive = pathFromUtf8(argument);
    auto destination = archive.parent_path() / archive.stem();
    if (destination.empty()) {
        return reportFailure(
            argument,
            Error{.kind = ErrorKind::Malformed, .what = "archive has no output folder name"}
        );
    }
    return extractArchive(argument, pathToUtf8(destination), {}, keyFile, verifyKeys);
}

}
