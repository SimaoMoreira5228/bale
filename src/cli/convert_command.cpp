#include "archive/reader.hpp"
#include "cli/archive_commands.hpp"
#include "cli/archive_output.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"
#include "formats/ar/reader.hpp"
#include "formats/cpio/reader.hpp"
#include "formats/sevenzip/reader.hpp"
#include "formats/tar/reader.hpp"
#include "formats/zip/reader.hpp"
#include "security/archive_path.hpp"

#include <chrono>
#include <filesystem>
#include <limits>
#include <print>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace bale::cli {

namespace {

constexpr std::size_t convertChunkSize = std::size_t{256} * 1024;
constexpr std::uint64_t maxSymlinkTargetBytes = 4096;
constexpr std::uint32_t permissionBits = 07777;
constexpr std::int64_t nanosecondsPerSecond = 1'000'000'000;
constexpr std::uint16_t fileTypeMask = 0170000;
constexpr std::uint16_t symlinkType = 0120000;

constexpr PathPolicy convertPathPolicy{
    .backslash = Backslash::Reject,
    .syntax = PathSyntax::Lenient,
    .windowsSafe = false,
};

std::optional<std::int64_t> joinTime(std::int64_t seconds, std::uint32_t nanoseconds) {
    constexpr auto max = std::numeric_limits<std::int64_t>::max();
    constexpr auto min = std::numeric_limits<std::int64_t>::min();
    if (seconds > (max - nanoseconds) / nanosecondsPerSecond ||
        seconds < min / nanosecondsPerSecond) {
        return std::nullopt;
    }
    return seconds * nanosecondsPerSecond + nanoseconds;
}

std::optional<std::uint32_t> maskedMode(std::optional<std::uint32_t> mode) {
    if (!mode) {
        return std::nullopt;
    }
    return *mode & permissionBits;
}

std::int64_t dosToUnix(std::uint16_t date, std::uint16_t time) {
    auto dos = zip::decodeDosDateTime(date, time);
    std::chrono::year_month_day day{
        std::chrono::year{dos.year},
        std::chrono::month{dos.month},
        std::chrono::day{dos.day},
    };
    if (!day.ok()) {
        return 0;
    }

    auto midnight = std::chrono::sys_days(day).time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(midnight).count();
    return seconds + std::int64_t{dos.hour} * 3600 + std::int64_t{dos.minute} * 60 + dos.second;
}

class Conversion {
  public:
    explicit Conversion(ArchiveOutput& output) : output_(output), scratch_(convertChunkSize) {
    }

    [[nodiscard]] ArchiveOutput& output() {
        return output_;
    }

    [[nodiscard]] std::span<std::byte> scratch() {
        return scratch_;
    }

    [[nodiscard]] std::string& text() {
        return text_;
    }

    [[nodiscard]] std::optional<ArchivePath> path(std::string_view raw) {
        return normalize(raw, path_);
    }

    [[nodiscard]] std::optional<ArchivePath> linkPath(std::string_view raw) {
        return normalize(raw, link_);
    }

    void skip(std::string_view name, std::string_view reason) {
        std::println(stderr, "bale: skipped {}: {}", escapeForTerminal(name, escaped_), reason);
    }

    template <typename Stream>
    [[nodiscard]] Result<void> copyFile(
        const ArchivePath& path,
        std::uint64_t size,
        const archive::EntryAttributes& attributes,
        Stream&& stream
    ) {
        auto begun = output_.beginFile(path.path, size, attributes);
        if (!begun) {
            return begun;
        }

        auto copied = stream([this](std::span<const std::byte> chunk) {
            return output_.writeFile(chunk);
        });
        if (!copied) {
            return copied;
        }
        return output_.endFile();
    }

  private:
    [[nodiscard]] std::optional<ArchivePath> normalize(std::string_view raw, std::string& out) {
        auto normalized =
            normalizeArchivePath(std::as_bytes(std::span(raw)), convertPathPolicy, limits_, out);
        if (!normalized) {
            skip(raw, normalized.error().what);
            return std::nullopt;
        }
        return *normalized;
    }

    ArchiveOutput& output_;
    Limits limits_;
    std::vector<std::byte> scratch_;
    std::string path_;
    std::string link_;
    std::string text_;
    std::string escaped_;
};

Result<void> convertTarEntry(Conversion& conversion, tar::Reader& reader, const tar::Entry& entry) {
    auto path = conversion.path(entry.path);
    if (!path) {
        return {};
    }

    archive::EntryAttributes attributes{
        .mtimeNanoseconds = joinTime(entry.mtimeSeconds, entry.mtimeNanoseconds),
        .mode = entry.mode & permissionBits,
    };
    switch (entry.kind) {
    case tar::EntryKind::Directory:
        return conversion.output().addDirectory(path->path, attributes);
    case tar::EntryKind::Regular:
        return conversion.copyFile(*path, entry.size, attributes, [&](auto&& sink) {
            return reader.streamData(conversion.scratch(), sink);
        });
    case tar::EntryKind::Symlink:
        if (entry.linkTarget.empty()) {
            conversion.skip(entry.path, "symlink without a target");
            return {};
        }
        return conversion.output().addSymlink(path->path, entry.linkTarget, attributes);
    case tar::EntryKind::HardLink: {
        if (!conversion.output().storesHardLinks()) {
            conversion.skip(entry.path, "the output format cannot store hard links");
            return {};
        }
        auto target = conversion.linkPath(entry.linkTarget);
        if (!target) {
            return {};
        }
        return conversion.output().addHardLink(path->path, target->path, attributes);
    }
    case tar::EntryKind::CharDevice:
    case tar::EntryKind::BlockDevice:
    case tar::EntryKind::Fifo:
    case tar::EntryKind::Other:
        break;
    }
    conversion.skip(entry.path, "special or unknown tar entry");
    return {};
}

Result<void> convertTar(Conversion& conversion, OpenedArchive archive) {
    auto source = openTarSource(std::move(archive.file), archive.format.compression);
    if (!source) {
        return std::unexpected(source.error());
    }

    tar::Reader reader(std::move(*source));
    while (true) {
        auto next = reader.next();
        if (!next) {
            return std::unexpected(next.error());
        }
        if (*next == nullptr) {
            return {};
        }

        auto converted = convertTarEntry(conversion, reader, **next);
        if (!converted) {
            return converted;
        }
    }
}

Result<void> convertZipEntry(
    Conversion& conversion,
    zip::Reader& reader,
    const zip::Entry& entry,
    std::string_view name
) {
    auto path = conversion.path(name);
    if (!path) {
        return {};
    }

    std::optional<std::uint32_t> mode;
    if (entry.unixMode) {
        mode = *entry.unixMode;
    }
    std::int64_t seconds =
        entry.modifiedUnixTime ? *entry.modifiedUnixTime : dosToUnix(entry.dosDate, entry.dosTime);
    archive::EntryAttributes attributes{
        .mtimeNanoseconds = joinTime(seconds, 0),
        .mode = maskedMode(mode),
    };
    if (path->directory) {
        return conversion.output().addDirectory(path->path, attributes);
    }

    if (entry.unixMode && (*entry.unixMode & fileTypeMask) == symlinkType) {
        if (entry.uncompressedSize == 0 || entry.uncompressedSize > maxSymlinkTargetBytes) {
            conversion.skip(name, "symlink target empty or too long");
            return {};
        }

        std::string& target = conversion.text();
        target.clear();
        auto read = reader.streamEntry(entry, conversion.scratch(), [&target](auto chunk) {
            target.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        if (!read) {
            return read;
        }
        attributes.mode.reset();
        return conversion.output().addSymlink(path->path, target, attributes);
    }

    return conversion.copyFile(*path, entry.uncompressedSize, attributes, [&](auto&& sink) {
        return reader.streamEntry(entry, conversion.scratch(), sink);
    });
}

Result<void> convertZip(Conversion& conversion, File file) {
    auto reader = zip::Reader::open(std::move(file));
    if (!reader) {
        return std::unexpected(reader.error());
    }

    auto cursor = reader->entries();
    zip::Entry entry;
    std::string nameStorage;
    while (true) {
        auto more = cursor.next(entry);
        if (!more) {
            return std::unexpected(more.error());
        }
        if (!*more) {
            return {};
        }

        auto name = zip::nameAsUtf8(entry, nameStorage);
        if (!name) {
            return std::unexpected(name.error());
        }
        auto converted = convertZipEntry(conversion, *reader, entry, *name);
        if (!converted) {
            return converted;
        }
    }
}

Result<void> convertSevenZipEntry(
    Conversion& conversion,
    sevenzip::Reader& reader,
    const sevenzip::Entry& entry
) {
    auto path = conversion.path(entry.name);
    if (!path) {
        return {};
    }

    archive::EntryAttributes attributes{
        .mtimeNanoseconds = entry.mtimeNanoseconds,
        .mode = maskedMode(entry.mode),
    };
    if (path->directory || entry.directory) {
        return conversion.output().addDirectory(path->path, attributes);
    }

    if (entry.mode && (*entry.mode & fileTypeMask) == symlinkType) {
        if (entry.size == 0 || entry.size > maxSymlinkTargetBytes) {
            conversion.skip(entry.name, "symlink target empty or too long");
            return {};
        }

        std::string& target = conversion.text();
        target.clear();
        auto read = reader.streamEntry(entry, conversion.scratch(), [&target](auto chunk) {
            target.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        if (!read) {
            return read;
        }
        attributes.mode.reset();
        return conversion.output().addSymlink(path->path, target, attributes);
    }

    return conversion.copyFile(*path, entry.size, attributes, [&](auto&& sink) {
        return reader.streamEntry(entry, conversion.scratch(), sink);
    });
}

Result<void> convertSevenZip(Conversion& conversion, File file) {
    auto reader = sevenzip::Reader::open(std::move(file));
    if (!reader) {
        return std::unexpected(reader.error());
    }

    for (const auto& entry : reader->entries()) {
        auto converted = convertSevenZipEntry(conversion, *reader, entry);
        if (!converted) {
            return converted;
        }
    }
    return {};
}

Result<void> convertArEntry(Conversion& conversion, ar::Reader& reader, const ar::Entry& entry) {
    auto path = conversion.path(entry.name);
    if (!path) {
        return {};
    }

    archive::EntryAttributes attributes{
        .mtimeNanoseconds = joinTime(entry.mtimeSeconds, 0),
        .mode = maskedMode(entry.mode),
    };
    return conversion.copyFile(*path, entry.size, attributes, [&](auto&& sink) {
        return reader.streamEntry(entry, conversion.scratch(), sink);
    });
}

Result<void> convertAr(Conversion& conversion, File file) {
    auto reader = ar::Reader::open(std::move(file));
    if (!reader) {
        return std::unexpected(reader.error());
    }

    for (const auto& entry : reader->entries()) {
        auto converted = convertArEntry(conversion, *reader, entry);
        if (!converted) {
            return converted;
        }
    }
    return {};
}

Result<void>
convertCpioEntry(Conversion& conversion, cpio::Reader& reader, const cpio::Entry& entry) {
    auto path = conversion.path(entry.name);
    if (!path) {
        return {};
    }

    archive::EntryAttributes attributes{
        .mtimeNanoseconds = joinTime(entry.mtimeSeconds, 0),
        .mode = maskedMode(entry.mode),
    };
    switch (entry.kind) {
    case cpio::EntryKind::Directory:
        return conversion.output().addDirectory(path->path, attributes);
    case cpio::EntryKind::Regular:
        return conversion.copyFile(*path, entry.size, attributes, [&](auto&& sink) {
            return reader.streamEntry(entry, conversion.scratch(), sink);
        });
    case cpio::EntryKind::Symlink: {
        if (entry.size == 0 || entry.size > maxSymlinkTargetBytes) {
            conversion.skip(entry.name, "symlink target empty or too long");
            return {};
        }

        std::string& target = conversion.text();
        target.clear();
        auto read = reader.streamEntry(entry, conversion.scratch(), [&target](auto chunk) {
            target.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            return Result<void>{};
        });
        if (!read) {
            return read;
        }
        attributes.mode.reset();
        return conversion.output().addSymlink(path->path, target, attributes);
    }
    case cpio::EntryKind::HardLink: {
        if (!conversion.output().storesHardLinks()) {
            conversion.skip(entry.name, "the output format cannot store hard links");
            return {};
        }
        auto target = conversion.linkPath(entry.linkTarget);
        if (!target) {
            return {};
        }
        return conversion.output().addHardLink(path->path, target->path, attributes);
    }
    case cpio::EntryKind::CharDevice:
    case cpio::EntryKind::BlockDevice:
    case cpio::EntryKind::Fifo:
    case cpio::EntryKind::Socket:
    case cpio::EntryKind::Other:
        break;
    }
    conversion.skip(entry.name, "special or unknown cpio entry");
    return {};
}

Result<void> convertCpio(Conversion& conversion, File file) {
    auto reader = cpio::Reader::open(std::move(file));
    if (!reader) {
        return std::unexpected(reader.error());
    }

    for (const auto& entry : reader->entries()) {
        auto converted = convertCpioEntry(conversion, *reader, entry);
        if (!converted) {
            return converted;
        }
    }
    return {};
}

Result<void> convertBaleEntry(
    Conversion& conversion,
    archive::Reader& reader,
    const archive::ManifestEntry& entry
) {
    auto path = conversion.path(entry.path);
    if (!path) {
        return {};
    }

    archive::EntryAttributes attributes{
        .mtimeNanoseconds = entry.mtimeNanoseconds,
        .mode = maskedMode(entry.mode),
    };
    switch (entry.kind) {
    case archive::EntryKind::Directory:
        return conversion.output().addDirectory(path->path, attributes);
    case archive::EntryKind::Regular:
        return conversion.copyFile(*path, entry.length, attributes, [&](auto&& sink) {
            return reader.streamFile(entry, sink);
        });
    case archive::EntryKind::Symlink:
        return conversion.output().addSymlink(path->path, entry.target, attributes);
    case archive::EntryKind::HardLink: {
        if (!conversion.output().storesHardLinks()) {
            conversion.skip(entry.path, "the output format cannot store hard links");
            return {};
        }
        auto target = conversion.linkPath(entry.target);
        if (!target) {
            return {};
        }
        return conversion.output().addHardLink(path->path, target->path, attributes);
    }
    }
    conversion.skip(entry.path, "unknown bale entry kind");
    return {};
}

Result<void> convertBale(Conversion& conversion, File file) {
    auto reader = archive::Reader::open(std::move(file));
    if (!reader) {
        return std::unexpected(reader.error());
    }

    for (const auto& entry : reader->manifest().entries) {
        auto converted = convertBaleEntry(conversion, *reader, entry);
        if (!converted) {
            return converted;
        }
    }
    return {};
}

Result<OutputSummary> convert(OpenedArchive archive, File file, const ConvertOptions& options) {
    OutputOptions outputOptions;
    outputOptions.format = options.format;
    outputOptions.level = options.level;
    auto output = ArchiveOutput::create(std::move(file), outputOptions);
    if (!output) {
        return std::unexpected(output.error());
    }

    Conversion conversion(*output);
    Result<void> converted;
    switch (archive.format.container) {
    case Container::Bale:
        converted = convertBale(conversion, std::move(archive.file));
        break;
    case Container::Zip:
        converted = convertZip(conversion, std::move(archive.file));
        break;
    case Container::SevenZip:
        converted = convertSevenZip(conversion, std::move(archive.file));
        break;
    case Container::Tar:
        converted = convertTar(conversion, std::move(archive));
        break;
    case Container::Ar:
        converted = convertAr(conversion, std::move(archive.file));
        break;
    case Container::Cpio:
        converted = convertCpio(conversion, std::move(archive.file));
        break;
    case Container::SingleFile:
    case Container::Unknown:
        converted = fail(ErrorKind::Unsupported, "only archives can be converted");
        break;
    }
    if (!converted) {
        return std::unexpected(converted.error());
    }
    return output->finish();
}

}

ExitCode
convertArchive(std::string_view input, std::string_view output, const ConvertOptions& options) {
    auto archive = openArchive(input);
    if (!archive) {
        return reportFailure(input, archive.error());
    }

    std::filesystem::path outputPath = pathFromUtf8(output);
    auto file = File::createNew(outputPath);
    if (!file) {
        return reportFailure(output, file.error());
    }

    auto summary = convert(std::move(*archive), std::move(*file), options);
    if (!summary) {
        std::error_code ignored;
        std::filesystem::remove(outputPath, ignored);
        return reportFailure(input, summary.error());
    }

    std::string escapedInput;
    std::string escapedOutput;
    std::println(
        "converted {} to {} ({}): {} entries, {} bytes total",
        escapeForTerminal(input, escapedInput),
        escapeForTerminal(output, escapedOutput),
        name(options.format),
        summary->entries,
        summary->archiveSize
    );
    return ExitCode::Ok;
}

}
