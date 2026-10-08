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
#include <string_view>
#include <system_error>
#include <vector>

namespace {

using bale::cli::ExitCode;

constexpr std::string_view usage = R"(usage: bale <command> [arguments]

commands:
  create <archive.bale> <dir> [options]
      --chunk-size <n>        chunk size in bytes, K or M suffix allowed (default 1M)
      --codec <raw|zstd>      chunk codec (default raw; zstd keeps raw when larger)
      --sync                  flush the archive to disk before writing its footer
  list <archive> [--long]   list entries, --long adds type, size and modification time
  test <archive>            check archive structure and entry checksums
  extract <archive> [options]
      -o, --output <dir>      extract into dir (default: current directory)
      --replace               replace existing regular files
      --skip-existing         keep existing files and skip those entries
      --allow-symlinks        create symlinks whose target stays inside the output
      --sync                  flush every file to disk before moving it into place
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

int runCreate(std::span<const std::string_view> arguments) {
    bale::cli::CreateOptions options;
    std::vector<std::string_view> positional;
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
        if (argument == "--codec") {
            if (index + 1 == arguments.size()) {
                return usageError("--codec needs raw or zstd");
            }
            ++index;
            if (arguments[index] == "raw") {
                options.codec = bale::CodecId::Raw;
            } else if (arguments[index] == "zstd") {
                options.codec = bale::CodecId::Zstd;
            } else {
                return usageError("--codec must be raw or zstd");
            }
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError("unknown option for create");
        }
        positional.push_back(argument);
    }

    if (positional.size() != 2) {
        return usageError("create takes an archive and a directory");
    }
    return exitWith(bale::cli::createArchive(positional[0], positional[1], options));
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
    printFormat("bale", "native format, raw and zstd chunks; not frozen");
    return exitWith(ExitCode::Ok);
}

int run(std::span<char*> argv) {
    if (argv.size() < 2) {
        return usageError("missing command");
    }
    std::vector<std::string_view> arguments(argv.begin() + 1, argv.end());

    std::string_view command = arguments.front();
    auto rest = std::span<const std::string_view>(arguments).subspan(1);
    if (command == "list") {
        return runList(rest);
    }
    if (command == "create") {
        return runCreate(rest);
    }
    if (command == "test") {
        return runTest(rest);
    }
    if (command == "extract") {
        return runExtract(rest);
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

// TODO: use wmain on Windows; the narrow argv there cannot carry every file name.
int main(int argc, char** argv) {
    try {
        return run(std::span(argv, static_cast<std::size_t>(argc)));
    } catch (const std::exception& error) {
        std::fputs("bale: internal error: ", stderr);
        std::fputs(error.what(), stderr);
        std::fputs("\n", stderr);
        return exitWith(ExitCode::Io);
    }
}
