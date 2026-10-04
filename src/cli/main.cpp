#include "cli/archive_commands.hpp"

#include <cstddef>
#include <cstdio>
#include <exception>
#include <print>
#include <span>
#include <string_view>
#include <vector>

namespace {

using bale::cli::ExitCode;

constexpr std::string_view usage = R"(usage: bale <command> [arguments]

commands:
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

int runFormats() {
    std::println("{:<6} {:<5} {:<5} {}", "format", "list", "test", "notes");
    std::println(
        "{:<6} {:<5} {:<5} {}",
        "zip",
        "yes",
        "yes",
        "stored and deflate, ZIP64, no encryption"
    );
    std::println(
        "{:<6} {:<5} {:<5} {}",
        "tar",
        "yes",
        "yes",
        "ustar, pax, GNU long names; no sparse files"
    );
    std::println(
        "{:<6} {:<5} {:<5} {}",
        "bale",
        "no",
        "no",
        "native format reader not implemented yet"
    );
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
