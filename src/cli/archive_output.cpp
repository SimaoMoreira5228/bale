#include "cli/archive_output.hpp"

#include "formats/compressed/output.hpp"

#include <algorithm>
#include <array>
#include <type_traits>

namespace bale::cli {

namespace {

constexpr std::size_t copyChunkSize = std::size_t{256} * 1024;
constexpr std::int64_t nanosecondsPerSecond = 1'000'000'000;
constexpr std::uint32_t defaultDirectoryMode = 0755;
constexpr std::uint32_t defaultFileMode = 0644;
constexpr std::uint32_t symlinkMode = 0777;

struct NamedFormat {
    std::string_view suffix;
    OutputFormat format;
};

constexpr std::array<NamedFormat, 8> suffixes{{
    {".bale", OutputFormat::Bale},
    {".zip", OutputFormat::Zip},
    {".7z", OutputFormat::SevenZip},
    {".tar", OutputFormat::Tar},
    {".tar.gz", OutputFormat::TarGzip},
    {".tgz", OutputFormat::TarGzip},
    {".tar.zst", OutputFormat::TarZstd},
    {".tzst", OutputFormat::TarZstd},
}};

bool endsWithIgnoringCase(std::string_view text, std::string_view suffix) {
    if (text.size() < suffix.size()) {
        return false;
    }

    auto tail = text.substr(text.size() - suffix.size());
    return std::ranges::equal(tail, suffix, [](char left, char right) {
        if (left >= 'A' && left <= 'Z') {
            left = static_cast<char>(left - 'A' + 'a');
        }
        return left == right;
    });
}

struct SplitTime {
    std::int64_t seconds = 0;
    std::uint32_t nanoseconds = 0;
};

SplitTime splitTime(std::int64_t nanoseconds) {
    auto seconds = nanoseconds / nanosecondsPerSecond;
    auto rest = nanoseconds % nanosecondsPerSecond;
    if (rest < 0) {
        --seconds;
        rest += nanosecondsPerSecond;
    }
    return SplitTime{
        .seconds = seconds,
        .nanoseconds = static_cast<std::uint32_t>(rest),
    };
}

tar::WriteEntry tarEntry(
    std::string_view path,
    const archive::EntryAttributes& attributes,
    tar::EntryKind kind,
    std::uint32_t defaultMode
) {
    tar::WriteEntry entry{
        .path = path,
        .mode = attributes.mode.value_or(defaultMode),
        .kind = kind,
    };
    if (attributes.mtimeNanoseconds) {
        auto time = splitTime(*attributes.mtimeNanoseconds);
        entry.mtimeSeconds = time.seconds;
        entry.mtimeNanoseconds = time.nanoseconds;
    }
    return entry;
}

zip::WriteEntry
zipEntry(std::string_view path, const archive::EntryAttributes& attributes, zip::WriteKind kind) {
    zip::WriteEntry entry{
        .path = path,
        .mode = attributes.mode,
        .kind = kind,
    };
    if (attributes.mtimeNanoseconds) {
        entry.mtimeSeconds = splitTime(*attributes.mtimeNanoseconds).seconds;
    }
    return entry;
}

sevenzip::WriteEntry sevenZipEntry(
    std::string_view path,
    const archive::EntryAttributes& attributes,
    sevenzip::WriteKind kind
) {
    return sevenzip::WriteEntry{
        .path = path,
        .mtimeNanoseconds = attributes.mtimeNanoseconds,
        .mode = attributes.mode,
        .kind = kind,
    };
}

Compression tarCompression(OutputFormat format) {
    switch (format) {
    case OutputFormat::TarGzip:
        return Compression::Gzip;
    case OutputFormat::TarZstd:
        return Compression::Zstd;
    case OutputFormat::Bale:
    case OutputFormat::Zip:
    case OutputFormat::SevenZip:
    case OutputFormat::Tar:
        break;
    }
    return Compression::None;
}

}

std::optional<OutputFormat> parseOutputFormat(std::string_view text) {
    for (const auto& named : suffixes) {
        if (named.suffix.substr(1) == text) {
            return named.format;
        }
    }
    return std::nullopt;
}

std::optional<OutputFormat> outputFormatFromName(std::string_view path) {
    for (const auto& named : suffixes) {
        if (endsWithIgnoringCase(path, named.suffix)) {
            return named.format;
        }
    }
    return std::nullopt;
}

std::string_view name(OutputFormat format) {
    switch (format) {
    case OutputFormat::Bale:
        return "bale";
    case OutputFormat::Zip:
        return "zip";
    case OutputFormat::SevenZip:
        return "7z";
    case OutputFormat::Tar:
        return "tar";
    case OutputFormat::TarGzip:
        return "tar.gz";
    case OutputFormat::TarZstd:
        return "tar.zst";
    }
    return "unknown";
}

std::optional<std::string_view> checkOutputLevel(OutputFormat format, int level) {
    switch (format) {
    case OutputFormat::SevenZip:
        // NOTE: codec-specific ranges are validated with the codec in hand
        // by create and convert; 0-9 covers lzma1, lzma2 and deflate.
        if (level < 0 || level > 9) {
            return "--level must be between 0 and 9 for 7z";
        }
        return std::nullopt;
    case OutputFormat::Zip:
        if (level < 0 || level > 9) {
            return "--level must be between 0 and 9 for zip";
        }
        return std::nullopt;
    case OutputFormat::TarGzip:
        if (level < 1 || level > 9) {
            return "--level must be between 1 and 9 for tar.gz";
        }
        return std::nullopt;
    case OutputFormat::TarZstd:
        if (level < 1 || level > 22) {
            return "--level must be between 1 and 22 for tar.zst";
        }
        return std::nullopt;
    case OutputFormat::Tar:
        return "--level does not apply to tar";
    case OutputFormat::Bale:
        break;
    }
    return std::nullopt;
}

Result<ArchiveOutput> ArchiveOutput::create(File file, const OutputOptions& options) {
    switch (options.format) {
    case OutputFormat::Bale: {
        auto writer = archive::Writer::create(std::move(file), options.native);
        if (!writer) {
            return std::unexpected(writer.error());
        }
        return ArchiveOutput(Sink(std::move(*writer)), options.format, false);
    }
    case OutputFormat::Zip: {
        zip::WriterOptions zipOptions;
        zipOptions.level = options.level.value_or(zip::defaultDeflateLevel);
        auto writer = zip::Writer::create(std::move(file), zipOptions);
        if (!writer) {
            return std::unexpected(writer.error());
        }
        return ArchiveOutput(Sink(std::move(*writer)), options.format, options.native.durable);
    }
    case OutputFormat::Tar:
    case OutputFormat::TarGzip:
    case OutputFormat::TarZstd: {
        auto output = CompressedOutput::create(
            std::move(file),
            tarCompression(options.format),
            options.level
        );
        if (!output) {
            return std::unexpected(output.error());
        }
        return ArchiveOutput(
            Sink(tar::Writer(std::move(*output))),
            options.format,
            options.native.durable
        );
    }
    case OutputFormat::SevenZip: {
        sevenzip::WriterOptions sevenZipOptions;
        sevenZipOptions.codec = options.sevenZipCodec;
        sevenZipOptions.level = options.sevenZipLevel;
        sevenZipOptions.solid = options.sevenZipSolid;
        auto writer = sevenzip::Writer::create(std::move(file), sevenZipOptions);
        if (!writer) {
            return std::unexpected(writer.error());
        }
        return ArchiveOutput(Sink(std::move(*writer)), options.format, options.native.durable);
    }
    }
    return fail(ErrorKind::Unsupported, "unknown output format");
}

Result<void> ArchiveOutput::addSignSeed(crypto::SecretBytes seed) {
    if (auto* native = std::get_if<archive::Writer>(&sink_)) {
        return native->addSignSeed(std::move(seed));
    }
    return fail(ErrorKind::Malformed, "signing applies only to bale archives");
}

Result<void>
ArchiveOutput::addDirectory(std::string_view path, const archive::EntryAttributes& attributes) {
    if (auto* native = std::get_if<archive::Writer>(&sink_)) {
        return native->addDirectory(path, attributes);
    }
    if (auto* tarWriter = std::get_if<tar::Writer>(&sink_)) {
        return tarWriter->add(
            tarEntry(path, attributes, tar::EntryKind::Directory, defaultDirectoryMode)
        );
    }
    if (auto* sevenZip = std::get_if<sevenzip::Writer>(&sink_)) {
        return sevenZip->add(sevenZipEntry(path, attributes, sevenzip::WriteKind::Directory));
    }
    return std::get<zip::Writer>(sink_).add(zipEntry(path, attributes, zip::WriteKind::Directory));
}

Result<void> ArchiveOutput::addSymlink(
    std::string_view path,
    std::string_view target,
    const archive::EntryAttributes& attributes
) {
    if (auto* native = std::get_if<archive::Writer>(&sink_)) {
        return native->addSymlink(path, target, attributes);
    }
    if (auto* tarWriter = std::get_if<tar::Writer>(&sink_)) {
        auto entry = tarEntry(path, attributes, tar::EntryKind::Symlink, symlinkMode);
        entry.linkTarget = target;
        return tarWriter->add(entry);
    }
    if (auto* sevenZip = std::get_if<sevenzip::Writer>(&sink_)) {
        auto entry = sevenZipEntry(path, attributes, sevenzip::WriteKind::Symlink);
        entry.linkTarget = target;
        return sevenZip->add(entry);
    }
    auto entry = zipEntry(path, attributes, zip::WriteKind::Symlink);
    entry.linkTarget = target;
    return std::get<zip::Writer>(sink_).add(entry);
}

Result<void> ArchiveOutput::addHardLink(
    std::string_view path,
    std::string_view target,
    const archive::EntryAttributes& attributes
) {
    if (auto* native = std::get_if<archive::Writer>(&sink_)) {
        return native->addHardLink(path, target);
    }
    if (auto* tarWriter = std::get_if<tar::Writer>(&sink_)) {
        auto entry = tarEntry(path, attributes, tar::EntryKind::HardLink, defaultFileMode);
        entry.linkTarget = target;
        return tarWriter->add(entry);
    }
    if (std::holds_alternative<sevenzip::Writer>(sink_)) {
        return fail(ErrorKind::Unsupported, "7z archives cannot store hard links");
    }
    return fail(ErrorKind::Unsupported, "ZIP archives cannot store hard links");
}

Result<void> ArchiveOutput::beginFile(
    std::string_view path,
    std::uint64_t size,
    const archive::EntryAttributes& attributes
) {
    if (auto* native = std::get_if<archive::Writer>(&sink_)) {
        return native->beginFile(path, attributes);
    }
    if (auto* tarWriter = std::get_if<tar::Writer>(&sink_)) {
        auto entry = tarEntry(path, attributes, tar::EntryKind::Regular, defaultFileMode);
        entry.size = size;
        return tarWriter->add(entry);
    }
    if (auto* sevenZip = std::get_if<sevenzip::Writer>(&sink_)) {
        auto entry = sevenZipEntry(path, attributes, sevenzip::WriteKind::File);
        entry.size = size;
        return sevenZip->add(entry);
    }
    auto entry = zipEntry(path, attributes, zip::WriteKind::File);
    entry.size = size;
    return std::get<zip::Writer>(sink_).add(entry);
}

Result<void> ArchiveOutput::writeFile(std::span<const std::byte> data) {
    return std::visit(
        [data](auto& writer) -> Result<void> {
            if constexpr (std::is_same_v<std::decay_t<decltype(writer)>, archive::Writer>) {
                return writer.writeFile(data);
            } else {
                return writer.write(data);
            }
        },
        sink_
    );
}

Result<void> ArchiveOutput::endFile() {
    if (auto* native = std::get_if<archive::Writer>(&sink_)) {
        return native->endFile();
    }
    return {};
}

Result<void> ArchiveOutput::addFile(
    std::string_view path,
    const File& source,
    std::uint64_t size,
    const archive::EntryAttributes& attributes
) {
    if (auto* native = std::get_if<archive::Writer>(&sink_)) {
        return native->addFile(path, source, attributes);
    }

    auto begun = beginFile(path, size, attributes);
    if (!begun) {
        return begun;
    }
    if (scratch_.empty()) {
        scratch_.resize(copyChunkSize);
    }

    std::uint64_t offset = 0;
    while (offset < size) {
        auto want = static_cast<std::size_t>(std::min<std::uint64_t>(size - offset, copyChunkSize));
        auto count = source.readAt(offset, std::span(scratch_).first(want));
        if (!count) {
            return std::unexpected(count.error());
        }
        if (*count == 0) {
            return fail(ErrorKind::Io, "file shrank while being archived");
        }

        auto written = writeFile(std::span(scratch_).first(*count));
        if (!written) {
            return written;
        }
        offset += *count;
    }

    auto extra = source.readAt(size, std::span(scratch_).first(1));
    if (!extra) {
        return std::unexpected(extra.error());
    }
    if (*extra != 0) {
        return fail(ErrorKind::Io, "file grew while being archived");
    }
    return endFile();
}

Result<OutputSummary> ArchiveOutput::finish() {
    if (auto* native = std::get_if<archive::Writer>(&sink_)) {
        auto summary = native->finish();
        if (!summary) {
            return std::unexpected(summary.error());
        }
        return OutputSummary{
            .entries = summary->entries,
            .archiveSize = summary->archiveSize,
            .native = *summary,
        };
    }

    std::uint64_t entries = 0;
    Result<std::uint64_t> size = std::visit(
        [this, &entries](auto& writer) -> Result<std::uint64_t> {
            if constexpr (std::is_same_v<std::decay_t<decltype(writer)>, archive::Writer>) {
                return fail(ErrorKind::Malformed, "native writer handled above");
            } else {
                entries = writer.entries();
                return writer.finish(durable_);
            }
        },
        sink_
    );
    if (!size) {
        return std::unexpected(size.error());
    }
    return OutputSummary{
        .entries = entries,
        .archiveSize = *size,
    };
}

}
