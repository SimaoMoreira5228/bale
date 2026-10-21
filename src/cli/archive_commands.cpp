#include "cli/archive_commands.hpp"

#include "archive/reader.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"
#include "cli/unlock.hpp"
#include "formats/ar/reader.hpp"
#include "formats/compressed/stream.hpp"
#include "formats/cpio/reader.hpp"
#include "formats/detect.hpp"
#include "formats/sevenzip/reader.hpp"
#include "formats/tar/reader.hpp"
#include "formats/tar/source.hpp"
#include "formats/zip/reader.hpp"
#include "io/file.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <print>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace bale::cli {

Result<void> requireSignatures(const archive::Reader& reader, const VerifyKeys& keys) {
    if (keys.empty()) {
        return {};
    }
    std::vector<std::array<std::byte, archive::signerIdSize>> keyViews(keys.begin(), keys.end());
    return reader.verifySignatures(keyViews);
}

namespace {

constexpr std::int64_t earliestPrintableTime = -62135596800;
constexpr std::int64_t latestPrintableTime = 253402300799;
constexpr std::size_t testChunkSize = std::size_t{64} * 1024;

struct CivilTime {
    int year = 0;
    unsigned month = 0;
    unsigned day = 0;
    unsigned hour = 0;
    unsigned minute = 0;
};

[[nodiscard]] std::optional<CivilTime> civilFromUnix(std::int64_t seconds) {
    if (seconds < earliestPrintableTime || seconds > latestPrintableTime) {
        return std::nullopt;
    }

    std::chrono::sys_seconds point{std::chrono::seconds{seconds}};
    auto midnight = std::chrono::floor<std::chrono::days>(point);
    std::chrono::year_month_day date{midnight};
    std::chrono::hh_mm_ss time{point - midnight};
    return CivilTime{
        .year = static_cast<int>(date.year()),
        .month = static_cast<unsigned>(date.month()),
        .day = static_cast<unsigned>(date.day()),
        .hour = static_cast<unsigned>(time.hours().count()),
        .minute = static_cast<unsigned>(time.minutes().count()),
    };
}

void printRow(
    char kind,
    std::optional<std::uint64_t> size,
    std::optional<CivilTime> time,
    std::string_view name,
    std::string_view linkTarget = {}
) {
    if (size) {
        std::print("{} {:>14} ", kind, *size);
    } else {
        std::print("{} {:>14} ", kind, "-");
    }

    if (time) {
        std::print(
            "{:04}-{:02}-{:02} {:02}:{:02} {}",
            time->year,
            time->month,
            time->day,
            time->hour,
            time->minute,
            name
        );
    } else {
        std::print("{:16} {}", "", name);
    }

    if (linkTarget.empty()) {
        std::println("");
    } else {
        std::println(" -> {}", linkTarget);
    }
}

[[nodiscard]] bool isZipDirectory(const zip::Entry& entry) {
    return entry.name.ends_with('/');
}

[[nodiscard]] char zipKind(const zip::Entry& entry) {
    constexpr std::uint16_t fileTypeMask = 0170000;
    constexpr std::uint16_t symlinkType = 0120000;

    if (entry.unixMode && (*entry.unixMode & fileTypeMask) == symlinkType) {
        return 'l';
    }
    if (isZipDirectory(entry)) {
        return 'd';
    }
    return '-';
}

[[nodiscard]] std::optional<CivilTime> zipTime(const zip::Entry& entry) {
    if (entry.modifiedUnixTime) {
        return civilFromUnix(*entry.modifiedUnixTime);
    }

    auto dos = zip::decodeDosDateTime(entry.dosDate, entry.dosTime);
    return CivilTime{
        .year = dos.year,
        .month = dos.month,
        .day = dos.day,
        .hour = dos.hour,
        .minute = dos.minute,
    };
}

[[nodiscard]] char tarKind(tar::EntryKind kind) {
    switch (kind) {
    case tar::EntryKind::Regular:
        return '-';
    case tar::EntryKind::HardLink:
        return 'h';
    case tar::EntryKind::Symlink:
        return 'l';
    case tar::EntryKind::CharDevice:
        return 'c';
    case tar::EntryKind::BlockDevice:
        return 'b';
    case tar::EntryKind::Directory:
        return 'd';
    case tar::EntryKind::Fifo:
        return 'p';
    case tar::EntryKind::Other:
        return '?';
    }
    return '?';
}

ExitCode listZip(std::string_view argument, File file, const ListOptions& options) {
    auto reader = zip::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    auto cursor = reader->entries();
    zip::Entry entry;
    std::string escaped;
    std::string nameStorage;
    while (true) {
        auto more = cursor.next(entry);
        if (!more) {
            return reportFailure(argument, more.error());
        }
        if (!*more) {
            return ExitCode::Ok;
        }

        auto utf8Name = zip::nameAsUtf8(entry, nameStorage);
        if (!utf8Name) {
            return reportFailure(argument, utf8Name.error());
        }
        auto name = escapeForTerminal(*utf8Name, escaped);
        if (options.detailed) {
            printRow(zipKind(entry), entry.uncompressedSize, zipTime(entry), name);
        } else {
            std::println("{}", name);
        }
    }
}

[[nodiscard]] std::optional<CivilTime> sevenZipTime(const sevenzip::Entry& entry) {
    if (!entry.mtimeNanoseconds) {
        return std::nullopt;
    }

    constexpr std::int64_t perSecond = 1'000'000'000;
    std::int64_t seconds = *entry.mtimeNanoseconds / perSecond;
    if (*entry.mtimeNanoseconds % perSecond < 0) {
        --seconds;
    }
    return civilFromUnix(seconds);
}

ExitCode listSevenZip(std::string_view argument, File file, const ListOptions& options) {
    auto reader = sevenzip::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::string escaped;
    for (const auto& entry : reader->entries()) {
        auto name = escapeForTerminal(entry.name, escaped);
        if (!options.detailed) {
            std::println("{}", name);
            continue;
        }

        printRow(entry.directory ? 'd' : '-', entry.size, sevenZipTime(entry), name);
    }
    return ExitCode::Ok;
}

ExitCode listTar(std::string_view argument, OpenedArchive archive, const ListOptions& options) {
    auto source = openTarSource(std::move(archive.file), archive.format.compression);
    if (!source) {
        return reportFailure(argument, source.error());
    }

    tar::Reader reader(std::move(*source));
    std::string escapedPath;
    std::string escapedTarget;
    while (true) {
        auto next = reader.next();
        if (!next) {
            return reportFailure(argument, next.error());
        }

        const tar::Entry* entry = *next;
        if (entry == nullptr) {
            return ExitCode::Ok;
        }

        auto path = escapeForTerminal(entry->path, escapedPath);
        if (!options.detailed) {
            std::println("{}", path);
            continue;
        }

        printRow(
            tarKind(entry->kind),
            entry->size,
            civilFromUnix(entry->mtimeSeconds),
            path,
            escapeForTerminal(entry->linkTarget, escapedTarget)
        );
    }
}

[[nodiscard]] char cpioKind(cpio::EntryKind kind) {
    switch (kind) {
    case cpio::EntryKind::Regular:
        return '-';
    case cpio::EntryKind::Directory:
        return 'd';
    case cpio::EntryKind::Symlink:
        return 'l';
    case cpio::EntryKind::HardLink:
        return 'h';
    case cpio::EntryKind::CharDevice:
        return 'c';
    case cpio::EntryKind::BlockDevice:
        return 'b';
    case cpio::EntryKind::Fifo:
        return 'p';
    case cpio::EntryKind::Socket:
        return 's';
    case cpio::EntryKind::Other:
        return '?';
    }
    return '?';
}

ExitCode listAr(std::string_view argument, File file, const ListOptions& options) {
    auto reader = ar::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::string escaped;
    for (const auto& entry : reader->entries()) {
        auto name = escapeForTerminal(entry.name, escaped);
        if (!options.detailed) {
            std::println("{}", name);
            continue;
        }

        printRow('-', entry.size, civilFromUnix(entry.mtimeSeconds), name);
    }
    return ExitCode::Ok;
}

ExitCode listCpio(std::string_view argument, File file, const ListOptions& options) {
    auto reader = cpio::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::string escapedPath;
    std::string escapedTarget;
    for (const auto& entry : reader->entries()) {
        auto path = escapeForTerminal(entry.name, escapedPath);
        if (!options.detailed) {
            std::println("{}", path);
            continue;
        }

        printRow(
            cpioKind(entry.kind),
            entry.size,
            civilFromUnix(entry.mtimeSeconds),
            path,
            escapeForTerminal(entry.linkTarget, escapedTarget)
        );
    }
    return ExitCode::Ok;
}

[[nodiscard]] char baleKind(archive::EntryKind kind) {
    switch (kind) {
    case archive::EntryKind::Regular:
        return '-';
    case archive::EntryKind::Directory:
        return 'd';
    case archive::EntryKind::Symlink:
        return 'l';
    case archive::EntryKind::HardLink:
        return 'h';
    }
    return '?';
}

[[nodiscard]] std::optional<CivilTime> baleTime(const archive::ManifestEntry& entry) {
    constexpr std::int64_t perSecond = 1'000'000'000;
    if (!entry.mtimeNanoseconds) {
        return std::nullopt;
    }

    std::int64_t seconds = *entry.mtimeNanoseconds / perSecond;
    if (*entry.mtimeNanoseconds % perSecond < 0) {
        --seconds;
    }
    return civilFromUnix(seconds);
}

ExitCode listBale(std::string_view argument, File file, const ListOptions& options) {
    auto reader = archive::Reader::open(std::move(file));
    std::optional<archive::Reader> encrypted;
    if (!reader && reader.error().kind == ErrorKind::PasswordRequired) {
        auto unlock = buildUnlock(options.keyFile, true);
        if (!unlock) {
            return reportFailure(argument, unlock.error());
        }
        // NOTE: reopen the file for the encrypted path; the moved-from File is unusable.
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
    const archive::Reader& active = encrypted ? *encrypted : *reader;

    if (auto signed_ = requireSignatures(active, options.verifyKeys); !signed_) {
        return reportFailure(argument, signed_.error());
    }
    if (!options.verifyKeys.empty()) {
        std::println("signature: ok, signed by the verification key");
    }

    std::string escapedPath;
    std::string escapedTarget;
    for (const auto& entry : active.manifest().entries) {
        auto path = escapeForTerminal(entry.path, escapedPath);
        if (!options.detailed) {
            std::println("{}", path);
            continue;
        }

        printRow(
            baleKind(entry.kind),
            entry.length,
            baleTime(entry),
            path,
            escapeForTerminal(entry.target, escapedTarget)
        );
    }
    return ExitCode::Ok;
}

ExitCode testBale(
    std::string_view argument,
    File file,
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
    archive::Reader* activePtr = encrypted ? &*encrypted : &*reader;
    archive::Reader& active = *activePtr;

    if (auto signed_ = requireSignatures(active, verifyKeys); !signed_) {
        return reportFailure(argument, signed_.error());
    }

    auto report = active.verify(archive::VerifyMode::Content);
    if (!report) {
        return reportFailure(argument, report.error());
    }

    std::println(
        "ok: {} entries, {} chunks ({} bytes) match their BLAKE3 digests",
        active.manifest().entries.size(),
        report->chunksVerified,
        report->bytesVerified
    );
    if (!verifyKeys.empty()) {
        std::println("signature: ok, signed by the verification key");
    }
    if (report->unindexedDataRecords != 0) {
        std::println("note: {} unreferenced data records", report->unindexedDataRecords);
    }
    if (active.ignoredTrailingBytes() != 0) {
        std::println(
            "note: ignored {} trailing bytes after the footer",
            active.ignoredTrailingBytes()
        );
    }
    return ExitCode::Ok;
}

ExitCode testZip(std::string_view argument, File file) {
    auto reader = zip::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::vector<std::byte> scratch(testChunkSize);
    auto discard = [](std::span<const std::byte>) -> Result<void> {
        return {};
    };

    auto cursor = reader->entries();
    zip::Entry entry;
    std::string escaped;
    std::uint64_t failures = 0;
    ExitCode result = ExitCode::Ok;
    std::string nameStorage;
    while (true) {
        auto more = cursor.next(entry);
        if (!more) {
            return reportFailure(argument, more.error());
        }
        if (!*more) {
            break;
        }
        auto utf8Name = zip::nameAsUtf8(entry, nameStorage);
        if (!utf8Name) {
            return reportFailure(argument, utf8Name.error());
        }
        if (isZipDirectory(entry) && entry.uncompressedSize == 0) {
            continue;
        }

        auto checked = reader->streamEntry(entry, scratch, discard);
        if (checked) {
            continue;
        }

        ++failures;
        if (result == ExitCode::Ok) {
            result = exitCodeFor(checked.error().kind);
        }
        reportError(escapeForTerminal(*utf8Name, escaped), checked.error());
    }

    if (failures == 0) {
        std::println("ok: {} entries", reader->entryCount());
    } else {
        std::println("{} of {} entries failed", failures, reader->entryCount());
    }
    return result;
}

ExitCode testSevenZip(std::string_view argument, File file) {
    auto reader = sevenzip::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::vector<std::byte> scratch(testChunkSize);
    auto discard = [](std::span<const std::byte>) -> Result<void> {
        return {};
    };

    std::uint64_t failures = 0;
    ExitCode result = ExitCode::Ok;
    std::string escaped;
    for (const auto& entry : reader->entries()) {
        if (!entry.folder) {
            continue;
        }

        auto checked = reader->streamEntry(entry, scratch, discard);
        if (checked) {
            continue;
        }

        ++failures;
        if (result == ExitCode::Ok) {
            result = exitCodeFor(checked.error().kind);
        }
        reportError(escapeForTerminal(entry.name, escaped), checked.error());
    }

    if (failures == 0) {
        std::println("ok: {} entries", reader->entryCount());
    } else {
        std::println("{} of {} entries failed", failures, reader->entryCount());
    }
    return result;
}

ExitCode testAr(std::string_view argument, File file) {
    auto reader = ar::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::vector<std::byte> scratch(testChunkSize);
    auto discard = [](std::span<const std::byte>) -> Result<void> {
        return {};
    };

    std::uint64_t failures = 0;
    ExitCode result = ExitCode::Ok;
    std::string escaped;
    for (const auto& entry : reader->entries()) {
        auto checked = reader->streamEntry(entry, scratch, discard);
        if (checked) {
            continue;
        }

        ++failures;
        if (result == ExitCode::Ok) {
            result = exitCodeFor(checked.error().kind);
        }
        reportError(escapeForTerminal(entry.name, escaped), checked.error());
    }

    if (failures == 0) {
        std::println("ok: {} entries", reader->entryCount());
    } else {
        std::println("{} of {} entries failed", failures, reader->entryCount());
    }
    return result;
}

ExitCode testCpio(std::string_view argument, File file) {
    auto reader = cpio::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::vector<std::byte> scratch(testChunkSize);
    auto discard = [](std::span<const std::byte>) -> Result<void> {
        return {};
    };

    std::uint64_t failures = 0;
    ExitCode result = ExitCode::Ok;
    std::string escaped;
    for (const auto& entry : reader->entries()) {
        if (entry.kind != cpio::EntryKind::Regular && entry.kind != cpio::EntryKind::Symlink) {
            continue;
        }

        auto checked = reader->streamEntry(entry, scratch, discard);
        if (checked) {
            continue;
        }

        ++failures;
        if (result == ExitCode::Ok) {
            result = exitCodeFor(checked.error().kind);
        }
        reportError(escapeForTerminal(entry.name, escaped), checked.error());
    }

    if (failures == 0) {
        std::println("ok: {} entries", reader->entryCount());
    } else {
        std::println("{} of {} entries failed", failures, reader->entryCount());
    }
    return result;
}

ExitCode testTar(std::string_view argument, OpenedArchive archive) {
    auto source = openTarSource(std::move(archive.file), archive.format.compression);
    if (!source) {
        return reportFailure(argument, source.error());
    }

    tar::Reader reader(std::move(*source));
    std::uint64_t count = 0;
    while (true) {
        auto next = reader.next();
        if (!next) {
            return reportFailure(argument, next.error());
        }
        if (*next == nullptr) {
            break;
        }
        ++count;
    }

    std::println("ok: {} entries", count);
    return ExitCode::Ok;
}

ExitCode
listSingleFile(std::string_view argument, OpenedArchive archive, const ListOptions& options) {
    auto stream = CompressedStream::open(std::move(archive.file), archive.format.compression);
    if (!stream) {
        return reportFailure(argument, stream.error());
    }

    std::string normalized;
    auto path = singleFileName(argument, *stream, normalized);
    if (!path) {
        return reportFailure(argument, path.error());
    }

    std::string escaped;
    auto name = escapeForTerminal(path->path, escaped);
    if (!options.detailed) {
        std::println("{}", name);
        return ExitCode::Ok;
    }

    std::optional<CivilTime> time;
    const auto* header = stream->gzipHeader();
    if (header != nullptr && header->mtime != 0) {
        time = civilFromUnix(header->mtime);
    }
    printRow('-', std::nullopt, time, name);
    return ExitCode::Ok;
}

ExitCode testSingleFile(std::string_view argument, OpenedArchive archive) {
    auto stream = CompressedStream::open(std::move(archive.file), archive.format.compression);
    if (!stream) {
        return reportFailure(argument, stream.error());
    }

    std::vector<std::byte> scratch(testChunkSize);
    auto checked = stream->readAll(scratch, [](std::span<const std::byte>) -> Result<void> {
        return {};
    });
    if (!checked) {
        return reportFailure(argument, checked.error());
    }

    std::println("ok: {} bytes", stream->outputBytes());
    return ExitCode::Ok;
}

}

ExitCode exitCodeFor(ErrorKind kind) {
    switch (kind) {
    case ErrorKind::Truncated:
    case ErrorKind::Malformed:
        return ExitCode::InvalidArchive;
    case ErrorKind::Unsupported:
        return ExitCode::Unsupported;
    case ErrorKind::Integrity:
        return ExitCode::Integrity;
    case ErrorKind::LimitExceeded:
        return ExitCode::LimitExceeded;
    case ErrorKind::UnsafePath:
        return ExitCode::UnsafePath;
    case ErrorKind::PasswordRequired:
        return ExitCode::PasswordRequired;
    case ErrorKind::Io:
        return ExitCode::Io;
    case ErrorKind::AlreadyExists:
        return ExitCode::AlreadyExists;
    }
    return ExitCode::InvalidArchive;
}

void reportError(std::string_view context, const Error& error) {
    std::print(stderr, "bale: {}: {}: {}", context, name(error.kind), error.what);
    if (error.offset != Error::noOffset) {
        std::print(stderr, " at offset {}", error.offset);
    }
    if (error.systemCode != 0) {
        std::print(stderr, ": {}", std::system_category().message(error.systemCode));
    }
    std::println(stderr, "");
}

ExitCode reportFailure(std::string_view context, const Error& error) {
    reportError(context, error);
    return exitCodeFor(error.kind);
}

Result<OpenedArchive> openArchive(std::string_view argument) {
    auto file = File::openRead(pathFromUtf8(argument));
    if (!file) {
        return std::unexpected(file.error());
    }

    auto format = detectFormat(*file);
    if (!format) {
        return std::unexpected(format.error());
    }
    if (format->container == Container::Unknown) {
        return fail(ErrorKind::Unsupported, "unrecognized archive format");
    }

    return OpenedArchive{
        .file = std::move(*file),
        .format = *format,
    };
}

Result<tar::Source> openTarSource(File file, Compression compression) {
    if (compression == Compression::None) {
        return tar::Source::open(std::move(file));
    }

    auto stream = CompressedStream::open(std::move(file), compression);
    if (!stream) {
        return std::unexpected(stream.error());
    }
    return tar::Source(std::move(*stream));
}

Result<ArchivePath>
singleFileName(std::string_view archive, const CompressedStream& stream, std::string& out) {
    PathPolicy policy;
    Limits limits;
    const auto* header = stream.gzipHeader();
    if (header != nullptr && !header->name.empty()) {
        auto stored =
            normalizeArchivePath(std::as_bytes(std::span(header->name)), policy, limits, out);
        if (stored && stored->depth == 1 && !stored->directory) {
            return stored;
        }
    }

    auto leaf = pathToUtf8(pathFromUtf8(archive).filename());
    bool stripped = false;
    for (std::string_view suffix :
         {std::string_view(".gz"),
          std::string_view(".zst"),
          std::string_view(".xz"),
          std::string_view(".bz2")}) {
        if (leaf.size() > suffix.size() && leaf.ends_with(suffix)) {
            leaf.resize(leaf.size() - suffix.size());
            stripped = true;
            break;
        }
    }
    if (!stripped) {
        leaf += ".out";
    }
    return normalizeArchivePath(std::as_bytes(std::span(leaf)), policy, limits, out);
}

ExitCode listArchive(std::string_view argument, const ListOptions& options) {
    auto archive = openArchive(argument);
    if (!archive) {
        return reportFailure(argument, archive.error());
    }
    if (archive->format.container != Container::Bale && !options.verifyKeys.empty()) {
        return reportFailure(
            argument,
            Error{
                .kind = ErrorKind::Malformed,
                .what = "--verify-key applies only to bale archives"
            }
        );
    }

    switch (archive->format.container) {
    case Container::Bale:
        return listBale(argument, std::move(archive->file), options);
    case Container::Zip:
        return listZip(argument, std::move(archive->file), options);
    case Container::SevenZip:
        return listSevenZip(argument, std::move(archive->file), options);
    case Container::SingleFile:
        return listSingleFile(argument, std::move(*archive), options);
    case Container::Tar:
        return listTar(argument, std::move(*archive), options);
    case Container::Ar:
        return listAr(argument, std::move(archive->file), options);
    case Container::Cpio:
        return listCpio(argument, std::move(archive->file), options);
    case Container::Unknown:
    default:
        return reportFailure(
            argument,
            Error{.kind = ErrorKind::Unsupported, .what = "unrecognized archive format"}
        );
    }
}

ExitCode testArchive(
    std::string_view argument,
    const std::optional<std::string>& keyFile,
    const VerifyKeys& verifyKeys
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

    switch (archive->format.container) {
    case Container::Bale:
        return testBale(argument, std::move(archive->file), keyFile, verifyKeys);
    case Container::Zip:
        return testZip(argument, std::move(archive->file));
    case Container::SevenZip:
        return testSevenZip(argument, std::move(archive->file));
    case Container::SingleFile:
        return testSingleFile(argument, std::move(*archive));
    case Container::Tar:
        return testTar(argument, std::move(*archive));
    case Container::Ar:
        return testAr(argument, std::move(archive->file));
    case Container::Cpio:
        return testCpio(argument, std::move(archive->file));
    case Container::Unknown:
    default:
        return reportFailure(
            argument,
            Error{.kind = ErrorKind::Unsupported, .what = "unrecognized archive format"}
        );
    }
}

}
