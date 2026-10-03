#include "cli/archive_commands.hpp"

#include "cli/terminal_text.hpp"
#include "formats/detect.hpp"
#include "formats/tar/reader.hpp"
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

struct OpenedArchive {
    File file;
    ArchiveFormat format = ArchiveFormat::Unknown;
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
    std::uint64_t size,
    std::optional<CivilTime> time,
    std::string_view name,
    std::string_view linkTarget = {}
) {
    if (time) {
        std::print(
            "{} {:>14} {:04}-{:02}-{:02} {:02}:{:02} {}",
            kind,
            size,
            time->year,
            time->month,
            time->day,
            time->hour,
            time->minute,
            name
        );
    } else {
        std::print("{} {:>14} {:16} {}", kind, size, "", name);
    }

    if (linkTarget.empty()) {
        std::println("");
    } else {
        std::println(" -> {}", linkTarget);
    }
}

ExitCode fail(std::string_view context, const Error& error) {
    reportError(context, error);
    return exitCodeFor(error.kind);
}

[[nodiscard]] Result<OpenedArchive> openArchive(std::string_view argument) {
    auto file = File::openRead(std::filesystem::path(argument));
    if (!file) {
        return std::unexpected(file.error());
    }

    auto format = detectFormat(*file);
    if (!format) {
        return std::unexpected(format.error());
    }
    if (*format == ArchiveFormat::Unknown) {
        return bale::fail(ErrorKind::Unsupported, "unrecognized archive format");
    }
    if (*format == ArchiveFormat::Bale) {
        return bale::fail(ErrorKind::Unsupported, "native BALE archives cannot be read yet");
    }

    return OpenedArchive{
        .file = std::move(*file),
        .format = *format,
    };
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
        return fail(argument, reader.error());
    }

    auto cursor = reader->entries();
    zip::Entry entry;
    std::string escaped;
    while (true) {
        auto more = cursor.next(entry);
        if (!more) {
            return fail(argument, more.error());
        }
        if (!*more) {
            return ExitCode::Ok;
        }

        auto name = escapeForTerminal(entry.name, escaped);
        if (options.detailed) {
            printRow(zipKind(entry), entry.uncompressedSize, zipTime(entry), name);
        } else {
            std::println("{}", name);
        }
    }
}

ExitCode listTar(std::string_view argument, File file, const ListOptions& options) {
    auto reader = tar::Reader::open(std::move(file));
    if (!reader) {
        return fail(argument, reader.error());
    }

    std::string escapedPath;
    std::string escapedTarget;
    while (true) {
        auto next = reader->next();
        if (!next) {
            return fail(argument, next.error());
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

ExitCode testZip(std::string_view argument, File file) {
    auto reader = zip::Reader::open(std::move(file));
    if (!reader) {
        return fail(argument, reader.error());
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
    while (true) {
        auto more = cursor.next(entry);
        if (!more) {
            return fail(argument, more.error());
        }
        if (!*more) {
            break;
        }
        if (isZipDirectory(entry) && entry.uncompressedSize == 0) {
            continue;
        }

        auto checked = reader->streamStored(entry, scratch, discard);
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

ExitCode testTar(std::string_view argument, File file) {
    auto reader = tar::Reader::open(std::move(file));
    if (!reader) {
        return fail(argument, reader.error());
    }

    std::uint64_t count = 0;
    while (true) {
        auto next = reader->next();
        if (!next) {
            return fail(argument, next.error());
        }
        if (*next == nullptr) {
            break;
        }
        ++count;
    }

    std::println("ok: {} entries", count);
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

ExitCode listArchive(std::string_view argument, const ListOptions& options) {
    auto archive = openArchive(argument);
    if (!archive) {
        return fail(argument, archive.error());
    }

    if (archive->format == ArchiveFormat::Zip) {
        return listZip(argument, std::move(archive->file), options);
    }
    return listTar(argument, std::move(archive->file), options);
}

ExitCode testArchive(std::string_view argument) {
    auto archive = openArchive(argument);
    if (!archive) {
        return fail(argument, archive.error());
    }

    if (archive->format == ArchiveFormat::Zip) {
        return testZip(argument, std::move(archive->file));
    }
    return testTar(argument, std::move(archive->file));
}

}
