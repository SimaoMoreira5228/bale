#include "cli/archive_commands.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <limits>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace {

using bale::cli::ExitCode;

constexpr std::int32_t defaultZstdLevel = 3;
constexpr std::int32_t defaultLz4Level = 0;

constexpr std::string_view usage = R"(usage: bale <command> [arguments]

commands:
  create <archive.bale> <dir> [options]
      --chunk-size <n>        chunk size in bytes, K or M suffix allowed (default 1M)
      --preset <name>         fast, balanced (default), small, restore-fast or portable
      --codec <raw|zstd|lz4>  explicit chunk codec instead of a preset
      --level <n>             level for the chosen codec: zstd 1-22, lz4 0-12
      --sync                  flush the archive to disk before writing its footer
  update <archive.bale> <dir> [options]
      append a new snapshot of the directory, reusing unchanged chunks; takes create's options
  compact <archive.bale> <output.bale> [--sync]
      write the current snapshot to a new archive and keep the source
  list <archive> [--long]   list entries, --long adds type, size and modification time
  test <archive>            check archive structure and entry checksums
  info <archive>            show the format and, for .bale, the recorded compression profile
  extract <archive> [options]
      -o, --output <dir>      extract into dir (default: current directory)
      --replace               replace existing regular files
      --skip-existing         keep existing files and skip those entries
      --allow-symlinks        create symlinks whose target stays inside the output
      --sync                  flush every file to disk before moving it into place
  context add <path>         create <path>.bale from a file or directory
  context extract-here <archive.bale>
  context extract-folder <archive.bale>
  formats                   show which formats bale can read
  help                      show this message
)";

int exitWith(ExitCode code) {
    return static_cast<int>(code);
}

int usageError(std::string_view message) {
    std::println(stderr, "bale: {}", message);
    std::print(stderr, "{}", usage);
    return exitWith(ExitCode::Usage);
}

int runList(std::span<const std::string_view> arguments) {
    bale::cli::ListOptions options;
    std::string_view archive;
    for (std::string_view argument : arguments) {
        if (argument == "--long" || argument == "-l") {
            options.detailed = true;
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError("unknown option for list");
        }
        if (!archive.empty()) {
            return usageError("list takes one archive");
        }
        archive = argument;
    }

    if (archive.empty()) {
        return usageError("list needs an archive");
    }
    return exitWith(bale::cli::listArchive(archive, options));
}

std::optional<std::uint32_t> parseSize(std::string_view text) {
    std::uint64_t multiplier = 1;
    if (text.ends_with('K') || text.ends_with('k')) {
        multiplier = 1024;
        text.remove_suffix(1);
    } else if (text.ends_with('M') || text.ends_with('m')) {
        multiplier = std::uint64_t{1024} * 1024;
        text.remove_suffix(1);
    }

    std::uint64_t value = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || text.empty()) {
        return std::nullopt;
    }
    if (value > std::numeric_limits<std::uint32_t>::max() / multiplier) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value * multiplier);
}

std::optional<std::int32_t> parseLevel(std::string_view text) {
    std::int32_t value = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::string_view> checkLevel(bale::CodecId codec, std::int32_t level) {
    switch (codec) {
    case bale::CodecId::Raw:
        return "--level does not apply to --codec raw";
    case bale::CodecId::Zstd:
        if (level < 1 || level > 22) {
            return "--level must be between 1 and 22 for zstd";
        }
        return std::nullopt;
    case bale::CodecId::Lz4:
        if (level < 0 || level > 12) {
            return "--level must be between 0 and 12 for lz4";
        }
        return std::nullopt;
    }
    return "codec has no levels";
}

int runCreate(std::span<const std::string_view> arguments, bool update = false) {
    bale::cli::CreateOptions options;
    std::vector<std::string_view> positional;
    std::optional<std::int32_t> explicitLevel;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        if (argument == "--chunk-size") {
            if (index + 1 == arguments.size()) {
                return usageError("--chunk-size needs a size");
            }
            ++index;
            auto size = parseSize(arguments[index]);
            if (!size) {
                return usageError("invalid --chunk-size");
            }
            options.chunkSize = *size;
            continue;
        }
        if (argument == "--sync") {
            options.durable = true;
            continue;
        }
        if (argument == "--preset") {
            if (index + 1 == arguments.size()) {
                return usageError("--preset needs a name");
            }
            ++index;
            auto preset = bale::archive::parsePreset(arguments[index]);
            if (!preset) {
                return usageError(
                    "--preset must be fast, balanced, small, restore-fast or portable"
                );
            }
            options.compression = bale::archive::profileFor(*preset);
            continue;
        }
        if (argument == "--codec") {
            if (index + 1 == arguments.size()) {
                return usageError("--codec needs raw, zstd or lz4");
            }
            ++index;
            if (arguments[index] == "raw") {
                options.compression.codec = bale::CodecId::Raw;
                options.compression.level = 0;
            } else if (arguments[index] == "zstd") {
                options.compression.codec = bale::CodecId::Zstd;
                options.compression.level = defaultZstdLevel;
            } else if (arguments[index] == "lz4") {
                options.compression.codec = bale::CodecId::Lz4;
                options.compression.level = defaultLz4Level;
            } else {
                return usageError("--codec must be raw, zstd or lz4");
            }
            options.compression.preset.reset();
            continue;
        }
        if (argument == "--level") {
            if (index + 1 == arguments.size()) {
                return usageError("--level needs a number");
            }
            ++index;
            explicitLevel = parseLevel(arguments[index]);
            if (!explicitLevel) {
                return usageError("--level needs a number");
            }
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError(update ? "unknown option for update" : "unknown option for create");
        }
        positional.push_back(argument);
    }

    if (explicitLevel) {
        if (auto problem = checkLevel(options.compression.codec, *explicitLevel)) {
            return usageError(*problem);
        }
        options.compression.level = *explicitLevel;
        options.compression.preset.reset();
    }

    if (positional.size() != 2) {
        return usageError(
            update ? "update takes an archive and a directory"
                   : "create takes an archive and a directory"
        );
    }
    if (update) {
        return exitWith(bale::cli::updateArchive(positional[0], positional[1], options));
    }
    return exitWith(bale::cli::createArchive(positional[0], positional[1], options));
}

int runCompact(std::span<const std::string_view> arguments) {
    bool durable = false;
    std::vector<std::string_view> positional;
    for (std::string_view argument : arguments) {
        if (argument == "--sync") {
            durable = true;
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError("unknown option for compact");
        }
        positional.push_back(argument);
    }

    if (positional.size() != 2) {
        return usageError("compact takes a source archive and a new output path");
    }
    return exitWith(bale::cli::compactArchive(positional[0], positional[1], durable));
}

int runTest(std::span<const std::string_view> arguments) {
    if (arguments.size() != 1 || arguments[0].starts_with('-')) {
        return usageError("test takes exactly one archive");
    }
    return exitWith(bale::cli::testArchive(arguments[0]));
}

int runExtract(std::span<const std::string_view> arguments) {
    bale::ExtractPolicy policy;
    std::string_view archive;
    std::string_view output = ".";
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        if (argument == "-o" || argument == "--output") {
            if (index + 1 == arguments.size()) {
                return usageError("--output needs a directory");
            }
            ++index;
            output = arguments[index];
            continue;
        }
        if (argument == "--replace") {
            policy.overwrite = bale::OverwritePolicy::Replace;
            continue;
        }
        if (argument == "--skip-existing") {
            policy.overwrite = bale::OverwritePolicy::Skip;
            continue;
        }
        if (argument == "--allow-symlinks") {
            policy.symlinks = bale::SymlinkPolicy::AllowContained;
            continue;
        }
        if (argument == "--sync") {
            policy.durable = true;
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError("unknown option for extract");
        }
        if (!archive.empty()) {
            return usageError("extract takes one archive");
        }
        archive = argument;
    }

    if (archive.empty()) {
        return usageError("extract needs an archive");
    }
    return exitWith(bale::cli::extractArchive(archive, output, policy));
}

int runContext(std::span<const std::string_view> arguments) {
    if (arguments.size() != 2) {
        return usageError("context takes an action and one path");
    }
    if (arguments[0] == "add") {
        return exitWith(bale::cli::createArchiveFromPath(arguments[1]));
    }
    if (arguments[0] == "extract-here") {
        return exitWith(bale::cli::extractArchiveHere(arguments[1]));
    }
    if (arguments[0] == "extract-folder") {
        return exitWith(bale::cli::extractArchiveToFolder(arguments[1]));
    }
    return usageError("unknown context action");
}

void printFormat(std::string_view format, std::string_view notes) {
    std::println("{:<8} {:<5} {:<5} {:<8} {}", format, "yes", "yes", "yes", notes);
}

int runFormats() {
    std::println("{:<8} {:<5} {:<5} {:<8} {}", "format", "list", "test", "extract", "notes");
    printFormat("zip", "stored and deflate, ZIP64, no encryption");
    printFormat("tar", "ustar, pax, GNU long names; no sparse files");
    printFormat("tar.gz", "tar inside gzip, recognized by content; read as one stream");
    printFormat("tar.zst", "tar inside zstd, recognized by content; read as one stream");
    printFormat("gzip", "one compressed file, multi-member; named by FNAME or archive name");
    printFormat("zstd", "one compressed file, multi-frame, window up to 128 MiB");
    printFormat("bale", "native format, raw and zstd chunks, presets; not frozen");
    return exitWith(ExitCode::Ok);
}

int run(std::span<const std::string_view> argv) {
    if (argv.size() < 2) {
        return usageError("missing command");
    }
    auto arguments = argv.subspan(1);
    std::string_view command = arguments.front();
    auto rest = std::span<const std::string_view>(arguments).subspan(1);
    if (command == "list") {
        return runList(rest);
    }
    if (command == "create") {
        return runCreate(rest);
    }
    if (command == "update") {
        return runCreate(rest, true);
    }
    if (command == "compact") {
        return runCompact(rest);
    }
    if (command == "info") {
        if (rest.size() != 1 || rest[0].starts_with('-')) {
            return usageError("info takes exactly one archive");
        }
        return exitWith(bale::cli::describeArchive(rest[0]));
    }
    if (command == "test") {
        return runTest(rest);
    }
    if (command == "extract") {
        return runExtract(rest);
    }
    if (command == "context") {
        return runContext(rest);
    }
    if (command == "formats") {
        return runFormats();
    }
    if (command == "help" || command == "--help" || command == "-h") {
        std::print("{}", usage);
        return exitWith(ExitCode::Ok);
    }
    return usageError("unknown command");
}

}

#ifdef _WIN32
std::optional<std::string> toUtf8(std::wstring_view value) {
    if (value.empty()) {
        return std::string{};
    }
    if (std::cmp_greater(value.size(), std::numeric_limits<int>::max())) {
        return std::nullopt;
    }

    int wideLength = static_cast<int>(value.size());
    int byteLength = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        wideLength,
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (byteLength <= 0) {
        return std::nullopt;
    }

    std::string result(static_cast<std::size_t>(byteLength), '\0');
    int converted = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        wideLength,
        result.data(),
        byteLength,
        nullptr,
        nullptr
    );
    if (converted != byteLength) {
        return std::nullopt;
    }
    return result;
}

int wmain(int argc, wchar_t** argv) {
    try {
        std::vector<std::string> storage;
        storage.reserve(static_cast<std::size_t>(argc));
        for (int index = 0; index < argc; ++index) {
            auto converted = toUtf8(argv[index]);
            if (!converted) {
                return usageError("command line contains invalid UTF-16");
            }
            storage.push_back(std::move(*converted));
        }

        std::vector<std::string_view> arguments;
        arguments.reserve(storage.size());
        for (const auto& value : storage) {
            arguments.push_back(value);
        }
        return run(arguments);
    } catch (const std::exception& error) {
        std::fputs("bale: internal error: ", stderr);
        std::fputs(error.what(), stderr);
        std::fputs("\n", stderr);
        return exitWith(ExitCode::Io);
    }
}
#else
int main(int argc, char** argv) {
    try {
        std::vector<std::string_view> arguments;
        arguments.reserve(static_cast<std::size_t>(argc));
        for (int index = 0; index < argc; ++index) {
            arguments.emplace_back(argv[index]);
        }
        return run(arguments);
    } catch (const std::exception& error) {
        std::fputs("bale: internal error: ", stderr);
        std::fputs(error.what(), stderr);
        std::fputs("\n", stderr);
        return exitWith(ExitCode::Io);
    }
}
#endif
