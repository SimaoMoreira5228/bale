#include "cli/archive_commands.hpp"
#include "cli/unlock.hpp"

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

constexpr std::string_view usage = R"(usage: bale <command> [arguments]

commands:
  create <archive> <dir> [options]
      --format <name>         bale, zip, 7z, tar, tar.gz or tar.zst (default: from the extension)
      --level <n>             zip 0-9 (0 stores), tar.gz 1-9, tar.zst 1-22, 7z depends on --codec,
                              bale: see --codec
      --codec <name>          bale: raw, zstd, lz4, lzma2 or brotli; 7z: copy, lzma1, lzma2,
                              deflate or bzip2
      --solid, --no-solid     7z only: one solid block (default) or one folder per file
      --sync                  flush the archive to disk before finishing
    native .bale only:
      --chunk-size <n>        chunk size in bytes, K or M suffix allowed (default 1M, fixed only)
      --chunking <name>       fixed (default) or cdc content-defined chunking
      --chunk-min <n>         cdc smallest chunk (default 256K)
      --chunk-target <n>      cdc average chunk size (default 1M)
      --chunk-max <n>         cdc largest chunk (default 4M)
      --preset <name>         fast, balanced (default), small, restore-fast or portable
      --codec <raw|zstd|lz4|lzma2|brotli>  explicit chunk codec instead of a preset
      --codec <...> --level   zstd levels 1-22, lz4 levels 0-12, lzma2 levels 0-9,
                              brotli levels 0-11
      --threads <1-64>        compression worker threads (default: CPU count, at most 8)
      --parity <spec>         emit stripe parity for the new generation: small (10+4),
                              capacity (17+3) or explicit <k>+<m> (bale only, off by default)
      --parity-shard-size <n> parity shard bytes, K or M suffix allowed (default 64K, needs --parity)
      --experimental-encryption  emit experimental encrypted records (bale only)
      --recipient <hex>       recipient X25519 public key, 64 hex chars (repeatable)
      --key-file <path>       recipient secret keys for update/unlock (one hex key per line)
      --sign <path>           sign the commit with Ed25519 seeds (one 64-hex-char seed per line)
      --verify-key <hex>      require a commit signature from this Ed25519 public key (repeatable)
  update <archive> <dir> [options]
      update a .bale snapshot or rewrite a .7z archive with a merged, sorted entry
      list; takes create's options, where --codec and --level follow the archive kind
  convert <input> <output> [--format <name>] [--codec <name>] [--level <n>]
      [--solid | --no-solid] [--image <n>]
      rewrite a bale, zip, 7z, tar, ar, cpio, cab, iso, wim or rpm archive entry by entry in another format
  compact <archive.bale> <output.bale> [--sync] [--experimental-encryption] [--key-file <path>]
      [--sign <path>] [--verify-key <hex>]
      write the current snapshot to a new archive and keep the source
  list <archive> [--long] [--image <n>] [--key-file <path>] [--verify-key <hex>]   list entries, --long adds type, size and modification time
  test <archive> [--image <n>] [--key-file <path>] [--verify-key <hex>]            check archive structure and entry checksums
  repair <archive> [--key-file <path>] [--verify-key <hex>]          repair stripe damage with parity, then check like test
  info <archive> [--key-file <path>] [--verify-key <hex>]            show the format and, for .bale, the recorded compression profile
  history <archive.bale> [--key-file <path>] [--verify-key <hex>]    list committed snapshots in a native archive
  extract <archive> [options]
      -o, --output <dir>      extract into dir (default: current directory)
      --image <n>             wim image index (default: bootable image, else image 1)
      --replace               replace existing regular files
      --skip-existing         keep existing files and skip those entries
      --allow-symlinks        create symlinks whose target stays inside the output
      --sync                  flush every file to disk before moving it into place
      --key-file <path>       recipient secret keys for encrypted archives
      --verify-key <hex>      require a commit signature from this Ed25519 public key (repeatable)
  context add <path>         create <path>.bale from a file or directory
  context extract-here <archive.bale>
  context extract-folder <archive.bale>
  formats                   show which formats bale can read and create
  help                      show this message

signatures: no PKI, no key servers, no web of trust. A signer holds an Ed25519 secret key
and a verifier holds the matching public key obtained out of band. --verify-key checks
only that the archive's latest commit was signed by that key, nothing more.
)";

int exitWith(ExitCode code) {
    return static_cast<int>(code);
}

std::optional<std::uint32_t> parseImageIndex(std::string_view text) {
    std::uint32_t value = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0) {
        return std::nullopt;
    }
    return value;
}

int usageError(std::string_view message) {
    std::println(stderr, "bale: {}", message);
    std::print(stderr, "{}", usage);
    return exitWith(ExitCode::Usage);
}

int runList(std::span<const std::string_view> arguments) {
    bale::cli::ListOptions options;
    std::string_view archive;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        if (argument == "--long" || argument == "-l") {
            options.detailed = true;
            continue;
        }
        if (argument == "--image") {
            if (index + 1 == arguments.size()) {
                return usageError("--image needs an index");
            }
            auto parsed = parseImageIndex(arguments[++index]);
            if (!parsed) {
                return usageError("--image needs a positive index");
            }
            options.imageIndex = *parsed;
            continue;
        }
        if (argument == "--key-file") {
            if (index + 1 == arguments.size()) {
                return usageError("--key-file needs a path");
            }
            options.keyFile = std::string(arguments[++index]);
            continue;
        }
        if (argument == "--verify-key") {
            if (index + 1 == arguments.size()) {
                return usageError("--verify-key needs a key");
            }
            ++index;
            auto parsed = bale::cli::parseVerifyKey(arguments[index]);
            if (!parsed) {
                return usageError("invalid --verify-key");
            }
            options.verifyKeys.push_back(*parsed);
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

int runHistory(std::span<const std::string_view> arguments) {
    std::optional<std::string> keyFile;
    bale::cli::VerifyKeys verifyKeys;
    std::string_view archive;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        const std::string_view argument = arguments[index];
        if (argument == "--key-file") {
            if (index + 1 == arguments.size()) {
                return usageError("--key-file needs a path");
            }
            keyFile = std::string(arguments[++index]);
            continue;
        }
        if (argument == "--verify-key") {
            if (index + 1 == arguments.size()) {
                return usageError("--verify-key needs a key");
            }
            auto parsed = bale::cli::parseVerifyKey(arguments[++index]);
            if (!parsed) {
                return usageError("invalid --verify-key");
            }
            verifyKeys.push_back(*parsed);
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError("unknown option for history");
        }
        if (!archive.empty()) {
            return usageError("history takes one archive");
        }
        archive = argument;
    }
    if (archive.empty()) {
        return usageError("history needs an archive");
    }
    return exitWith(bale::cli::historyArchive(archive, keyFile, verifyKeys));
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

std::optional<std::uint32_t> parseThreads(std::string_view text) {
    std::uint32_t value = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value < 1 ||
        value > bale::archive::maxWorkers) {
        return std::nullopt;
    }
    return value;
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
    return bale::cli::checkBaleCodecLevel(codec, level);
}

int runCreate(std::span<const std::string_view> arguments, bool update = false) {
    bale::cli::CreateOptions options;
    std::vector<std::string_view> positional;
    std::optional<std::int32_t> explicitLevel;
    std::optional<std::string> codecName;
    std::optional<bale::cli::OutputFormat> explicitFormat;
    std::string_view nativeOption;
    bool chunkSizeSet = false;
    bool cdcSizesSet = false;
    bool solidExplicit = false;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        if (argument == "--chunk-size" || argument == "--threads" || argument == "--preset" ||
            argument == "--chunking" || argument == "--chunk-min" || argument == "--chunk-target" ||
            argument == "--chunk-max" || argument == "--parity" ||
            argument == "--parity-shard-size") {
            nativeOption = argument;
        }
        if (argument == "--format") {
            if (index + 1 == arguments.size()) {
                return usageError("--format needs a name");
            }
            ++index;
            explicitFormat = bale::cli::parseOutputFormat(arguments[index]);
            if (!explicitFormat) {
                return usageError("--format must be bale, zip, 7z, tar, tar.gz or tar.zst");
            }
            continue;
        }
        if (argument == "--solid") {
            options.sevenZipSolid = true;
            solidExplicit = true;
            continue;
        }
        if (argument == "--no-solid") {
            options.sevenZipSolid = false;
            solidExplicit = true;
            continue;
        }
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
            chunkSizeSet = true;
            continue;
        }
        if (argument == "--chunking") {
            if (index + 1 == arguments.size()) {
                return usageError("--chunking needs fixed or cdc");
            }
            ++index;
            if (arguments[index] == "fixed") {
                options.chunkPolicy = bale::archive::ChunkPolicy::Fixed;
            } else if (arguments[index] == "cdc") {
                options.chunkPolicy = bale::archive::ChunkPolicy::Cdc;
            } else {
                return usageError("--chunking must be fixed or cdc");
            }
            continue;
        }
        if (argument == "--chunk-min" || argument == "--chunk-target" ||
            argument == "--chunk-max") {
            if (index + 1 == arguments.size()) {
                return usageError("chunk bound needs a size");
            }
            ++index;
            auto size = parseSize(arguments[index]);
            if (!size) {
                return usageError("invalid chunk bound");
            }
            if (argument == "--chunk-min") {
                options.cdc.min = *size;
            } else if (argument == "--chunk-target") {
                options.cdc.target = *size;
            } else {
                options.cdc.max = *size;
            }
            cdcSizesSet = true;
            continue;
        }
        if (argument == "--sync") {
            options.durable = true;
            continue;
        }
        if (argument == "--threads") {
            if (index + 1 == arguments.size()) {
                return usageError("--threads needs a count");
            }
            ++index;
            auto threads = parseThreads(arguments[index]);
            if (!threads) {
                return usageError("--threads must be between 1 and 64");
            }
            options.workers = *threads;
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
                return usageError("--codec needs a name");
            }
            ++index;
            codecName = std::string(arguments[index]);
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
        if (argument == "--experimental-encryption") {
            options.experimentalEncryption = true;
            continue;
        }
        if (argument == "--parity") {
            if (index + 1 == arguments.size()) {
                return usageError("--parity needs small, capacity or <k>+<m>");
            }
            ++index;
            auto parsed = bale::archive::parseParitySpec(arguments[index]);
            if (!parsed) {
                return usageError("--parity must be small, capacity or <k>+<m>");
            }
            options.parity = *parsed;
            continue;
        }
        if (argument == "--parity-shard-size") {
            if (index + 1 == arguments.size()) {
                return usageError("--parity-shard-size needs a size");
            }
            ++index;
            auto size = parseSize(arguments[index]);
            if (!size) {
                return usageError("invalid --parity-shard-size");
            }
            options.parityShardSize = size;
            continue;
        }
        if (argument == "--recipient") {
            if (index + 1 == arguments.size()) {
                return usageError("--recipient needs a 64-hex-character key");
            }
            ++index;
            auto parsed = bale::cli::parseRecipientHex(arguments[index]);
            if (!parsed) {
                return usageError("invalid --recipient key");
            }
            options.recipients.push_back(*parsed);
            continue;
        }
        if (argument == "--key-file") {
            if (index + 1 == arguments.size()) {
                return usageError("--key-file needs a path");
            }
            ++index;
            options.keyFile = std::string(arguments[index]);
            continue;
        }
        if (argument == "--sign") {
            if (index + 1 == arguments.size()) {
                return usageError("--sign needs a path");
            }
            ++index;
            options.signKeyFile = std::string(arguments[index]);
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError(update ? "unknown option for update" : "unknown option for create");
        }
        positional.push_back(argument);
    }

    if (positional.size() != 2) {
        return usageError(
            update ? "update takes an archive and a directory"
                   : "create takes an archive and a directory"
        );
    }

    if (update) {
        if (explicitFormat) {
            return usageError("update takes no --format; the archive kind is detected");
        }
        // NOTE: the archive kind is detected by updateArchive, so both codec
        // families are accepted here and the detected container decides.
        if (codecName) {
            bool mapped = false;
            if (bale::cli::applyBaleCodecName(options, *codecName)) {
                mapped = true;
            }
            if (auto codec = bale::cli::parseSevenZipCodec(*codecName)) {
                options.sevenZipCodec = *codec;
                mapped = true;
            }
            if (!mapped) {
                return usageError(
                    "--codec must be raw, zstd, lz4, lzma2, brotli, copy, lzma1, deflate or bzip2"
                );
            }
            options.codecName = std::move(codecName);
        }
        options.sevenZipSolidExplicit = solidExplicit;
        if (explicitLevel) {
            options.level = explicitLevel;
            bool sevenOnly = options.codecName &&
                bale::cli::parseSevenZipCodec(*options.codecName) &&
                !bale::cli::isBaleCodecName(*options.codecName);
            if (!sevenOnly) {
                if (auto problem = checkLevel(options.compression.codec, *explicitLevel)) {
                    return usageError(*problem);
                }
                options.compression.level = *explicitLevel;
                options.compression.preset.reset();
            }
        }
    } else {
        auto format =
            explicitFormat ? explicitFormat : bale::cli::outputFormatFromName(positional[0]);
        if (!format) {
            return usageError("cannot tell the format from the archive name; pass --format");
        }
        options.format = *format;
        if (options.format == bale::cli::OutputFormat::Bale) {
            if (solidExplicit) {
                return usageError("--solid and --no-solid apply only to 7z");
            }
            if (codecName) {
                if (!bale::cli::applyBaleCodecName(options, *codecName)) {
                    return usageError("--codec must be raw, zstd, lz4, lzma2 or brotli");
                }
            }
            if (explicitLevel) {
                if (auto problem = checkLevel(options.compression.codec, *explicitLevel)) {
                    return usageError(*problem);
                }
                options.compression.level = *explicitLevel;
                options.compression.preset.reset();
            }
        } else if (options.format == bale::cli::OutputFormat::SevenZip) {
            if (!nativeOption.empty()) {
                return usageError(
                    "--chunk-size, --chunking, --chunk-min, --chunk-target, --chunk-max, "
                    "--threads, --preset, --parity and --parity-shard-size apply only to bale"
                );
            }
            if (codecName) {
                auto codec = bale::cli::parseSevenZipCodec(*codecName);
                if (!codec) {
                    return usageError(
                        "--codec must be copy, lzma1, lzma2, deflate or bzip2 for 7z"
                    );
                }
                options.sevenZipCodec = *codec;
            }
            if (explicitLevel) {
                if (auto problem =
                        bale::cli::checkSevenZipLevel(options.sevenZipCodec, *explicitLevel)) {
                    return usageError(*problem);
                }
                options.sevenZipLevel = *explicitLevel;
            }
        } else {
            if (!nativeOption.empty()) {
                return usageError(
                    "--chunk-size, --chunking, --chunk-min, --chunk-target, --chunk-max, "
                    "--threads, --preset, --codec, --parity and --parity-shard-size apply only "
                    "to bale"
                );
            }
            if (codecName) {
                return usageError("--codec applies only to bale and 7z");
            }
            if (solidExplicit) {
                return usageError("--solid and --no-solid apply only to 7z");
            }
            if (explicitLevel) {
                if (auto problem = bale::cli::checkOutputLevel(options.format, *explicitLevel)) {
                    return usageError(*problem);
                }
                options.level = explicitLevel;
            }
        }
    }

    if (options.chunkPolicy == bale::archive::ChunkPolicy::Cdc) {
        if (chunkSizeSet) {
            return usageError("--chunk-size applies only to fixed chunking");
        }
        auto valid = bale::archive::validateCdcParams(options.cdc);
        if (!valid) {
            return usageError(valid.error().what);
        }
    } else if (cdcSizesSet) {
        return usageError("--chunk-min, --chunk-target and --chunk-max apply only to cdc");
    }

    if (!options.experimentalEncryption && !options.recipients.empty()) {
        return usageError("--recipient requires --experimental-encryption");
    }
    if (options.parityShardSize && !options.parity) {
        return usageError("--parity-shard-size needs --parity");
    }
    if (options.parity) {
        bale::archive::ParityConfig config = *options.parity;
        if (options.parityShardSize) {
            config.shardBytes = *options.parityShardSize;
        }
        if (auto valid = bale::archive::validateParityConfig(config); !valid) {
            return usageError(valid.error().what);
        }
    }
    if (options.experimentalEncryption && options.format != bale::cli::OutputFormat::Bale) {
        return usageError("--experimental-encryption applies only to bale");
    }
    if (options.signKeyFile && options.format != bale::cli::OutputFormat::Bale) {
        return usageError("--sign applies only to bale");
    }

    if (update) {
        return exitWith(bale::cli::updateArchive(positional[0], positional[1], options));
    }
    return exitWith(bale::cli::createArchive(positional[0], positional[1], options));
}

int runConvert(std::span<const std::string_view> arguments) {
    bale::cli::ConvertOptions options;
    std::optional<bale::cli::OutputFormat> explicitFormat;
    std::optional<std::int32_t> explicitLevel;
    std::optional<std::string> codecName;
    bool solidExplicit = false;
    std::vector<std::string_view> positional;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        if (argument == "--format" || argument == "--level" || argument == "--codec") {
            if (index + 1 == arguments.size()) {
                return usageError("--format, --level and --codec need a value");
            }
            ++index;
            if (argument == "--format") {
                explicitFormat = bale::cli::parseOutputFormat(arguments[index]);
                if (!explicitFormat) {
                    return usageError("--format must be bale, zip, 7z, tar, tar.gz or tar.zst");
                }
            } else if (argument == "--level") {
                explicitLevel = parseLevel(arguments[index]);
                if (!explicitLevel) {
                    return usageError("--level needs a number");
                }
            } else {
                codecName = std::string(arguments[index]);
            }
            continue;
        }
        if (argument == "--solid") {
            options.sevenZipSolid = true;
            solidExplicit = true;
            continue;
        }
        if (argument == "--no-solid") {
            options.sevenZipSolid = false;
            solidExplicit = true;
            continue;
        }
        if (argument == "--image") {
            if (index + 1 == arguments.size()) {
                return usageError("--image needs an index");
            }
            auto parsed = parseImageIndex(arguments[++index]);
            if (!parsed) {
                return usageError("--image needs a positive index");
            }
            options.imageIndex = *parsed;
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError("unknown option for convert");
        }
        positional.push_back(argument);
    }

    if (positional.size() != 2) {
        return usageError("convert takes an input archive and a new output path");
    }
    auto format = explicitFormat ? explicitFormat : bale::cli::outputFormatFromName(positional[1]);
    if (!format) {
        return usageError("cannot tell the format from the output name; pass --format");
    }
    options.format = *format;
    if (options.format == bale::cli::OutputFormat::SevenZip) {
        if (codecName) {
            auto codec = bale::cli::parseSevenZipCodec(*codecName);
            if (!codec) {
                return usageError("--codec must be copy, lzma1, lzma2, deflate or bzip2 for 7z");
            }
            options.sevenZipCodec = *codec;
        }
        if (explicitLevel) {
            if (auto problem =
                    bale::cli::checkSevenZipLevel(options.sevenZipCodec, *explicitLevel)) {
                return usageError(*problem);
            }
            options.sevenZipLevel = *explicitLevel;
        }
        return exitWith(bale::cli::convertArchive(positional[0], positional[1], options));
    }
    if (codecName) {
        return usageError("--codec applies only to 7z");
    }
    if (solidExplicit) {
        return usageError("--solid and --no-solid apply only to 7z");
    }
    if (explicitLevel) {
        if (*format == bale::cli::OutputFormat::Bale) {
            return usageError("convert to bale uses the default profile and takes no --level");
        }
        if (auto problem = bale::cli::checkOutputLevel(*format, *explicitLevel)) {
            return usageError(*problem);
        }
        options.level = explicitLevel;
    }
    return exitWith(bale::cli::convertArchive(positional[0], positional[1], options));
}

int runCompact(std::span<const std::string_view> arguments) {
    bool durable = false;
    bool experimental = false;
    std::optional<std::string> keyFile;
    std::optional<std::string> signKeyFile;
    bale::cli::VerifyKeys verifyKeys;
    std::vector<std::string_view> positional;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        if (argument == "--sync") {
            durable = true;
            continue;
        }
        if (argument == "--experimental-encryption") {
            experimental = true;
            continue;
        }
        if (argument == "--key-file") {
            if (index + 1 == arguments.size()) {
                return usageError("--key-file needs a path");
            }
            keyFile = std::string(arguments[++index]);
            continue;
        }
        if (argument == "--sign") {
            if (index + 1 == arguments.size()) {
                return usageError("--sign needs a path");
            }
            signKeyFile = std::string(arguments[++index]);
            continue;
        }
        if (argument == "--verify-key") {
            if (index + 1 == arguments.size()) {
                return usageError("--verify-key needs a key");
            }
            ++index;
            auto parsed = bale::cli::parseVerifyKey(arguments[index]);
            if (!parsed) {
                return usageError("invalid --verify-key");
            }
            verifyKeys.push_back(*parsed);
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
    return exitWith(
        bale::cli::compactArchive(
            positional[0],
            positional[1],
            durable,
            experimental,
            keyFile,
            signKeyFile,
            verifyKeys
        )
    );
}

int runTest(std::span<const std::string_view> arguments) {
    std::optional<std::string> keyFile;
    bale::cli::VerifyKeys verifyKeys;
    std::uint32_t imageIndex = 0;
    std::string_view archive;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        if (argument == "--key-file") {
            if (index + 1 == arguments.size()) {
                return usageError("--key-file needs a path");
            }
            keyFile = std::string(arguments[++index]);
            continue;
        }
        if (argument == "--image") {
            if (index + 1 == arguments.size()) {
                return usageError("--image needs an index");
            }
            auto parsed = parseImageIndex(arguments[++index]);
            if (!parsed) {
                return usageError("--image needs a positive index");
            }
            imageIndex = *parsed;
            continue;
        }
        if (argument == "--verify-key") {
            if (index + 1 == arguments.size()) {
                return usageError("--verify-key needs a key");
            }
            ++index;
            auto parsed = bale::cli::parseVerifyKey(arguments[index]);
            if (!parsed) {
                return usageError("invalid --verify-key");
            }
            verifyKeys.push_back(*parsed);
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError("test takes an archive and --key-file");
        }
        if (!archive.empty()) {
            return usageError("test takes exactly one archive");
        }
        archive = argument;
    }
    if (archive.empty()) {
        return usageError("test takes exactly one archive");
    }
    return exitWith(bale::cli::testArchive(archive, keyFile, verifyKeys, imageIndex));
}

int runRepair(std::span<const std::string_view> arguments) {
    std::optional<std::string> keyFile;
    bale::cli::VerifyKeys verifyKeys;
    std::string_view archive;
    for (std::size_t index = 0; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        if (argument == "--key-file") {
            if (index + 1 == arguments.size()) {
                return usageError("--key-file needs a path");
            }
            keyFile = std::string(arguments[++index]);
            continue;
        }
        if (argument == "--verify-key") {
            if (index + 1 == arguments.size()) {
                return usageError("--verify-key needs a key");
            }
            ++index;
            auto parsed = bale::cli::parseVerifyKey(arguments[index]);
            if (!parsed) {
                return usageError("invalid --verify-key");
            }
            verifyKeys.push_back(*parsed);
            continue;
        }
        if (argument.starts_with('-')) {
            return usageError("repair takes an archive and --key-file");
        }
        if (!archive.empty()) {
            return usageError("repair takes exactly one archive");
        }
        archive = argument;
    }
    if (archive.empty()) {
        return usageError("repair takes exactly one archive");
    }
    return exitWith(bale::cli::repairArchive(archive, keyFile, verifyKeys));
}

int runExtract(std::span<const std::string_view> arguments) {
    bale::ExtractPolicy policy;
    std::string_view archive;
    std::string_view output = ".";
    std::optional<std::string> keyFile;
    bale::cli::VerifyKeys verifyKeys;
    std::uint32_t imageIndex = 0;
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
        if (argument == "--image") {
            if (index + 1 == arguments.size()) {
                return usageError("--image needs an index");
            }
            auto parsed = parseImageIndex(arguments[++index]);
            if (!parsed) {
                return usageError("--image needs a positive index");
            }
            imageIndex = *parsed;
            continue;
        }
        if (argument == "--key-file") {
            if (index + 1 == arguments.size()) {
                return usageError("--key-file needs a path");
            }
            keyFile = std::string(arguments[++index]);
            continue;
        }
        if (argument == "--verify-key") {
            if (index + 1 == arguments.size()) {
                return usageError("--verify-key needs a key");
            }
            ++index;
            auto parsed = bale::cli::parseVerifyKey(arguments[index]);
            if (!parsed) {
                return usageError("invalid --verify-key");
            }
            verifyKeys.push_back(*parsed);
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
    return exitWith(
        bale::cli::extractArchive(archive, output, policy, keyFile, verifyKeys, imageIndex)
    );
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

void printFormat(std::string_view format, bool create, std::string_view notes) {
    std::println(
        "{:<8} {:<5} {:<5} {:<8} {:<7} {}",
        format,
        "yes",
        "yes",
        "yes",
        create ? "yes" : "no",
        notes
    );
}

int runFormats() {
    std::println(
        "{:<8} {:<5} {:<5} {:<8} {:<7} {}",
        "format",
        "list",
        "test",
        "extract",
        "create",
        "notes"
    );
    printFormat("zip", true, "stored and deflate, ZIP64, no encryption");
    printFormat(
        "7z",
        true,
        "copy, lzma1, lzma2, deflate, bzip2; standalone BCJ and one main-codec+BCJ chain; "
        "solid blocks decode from the block start; no encryption or other filters"
    );
    printFormat("tar", true, "ustar, pax, GNU long names; no sparse files");
    printFormat("tar.gz", true, "tar inside gzip, recognized by content; read as one stream");
    printFormat("tar.zst", true, "tar inside zstd, recognized by content; read as one stream");
    printFormat("tar.xz", false, "tar inside xz, recognized by content; read as one stream");
    printFormat("tar.bz2", false, "tar inside bzip2, recognized by content; read as one stream");
    printFormat("ar", false, "read-only; System V, GNU and BSD members, skips symbol tables");
    printFormat("cpio", false, "read-only; SVR4 newc and crc headers, no odc or binary headers");
    printFormat(
        "rpm",
        false,
        "read-only; v3/v4 lead, gzip/xz/zstd/bzip2 cpio payloads; signatures listed, never verified"
    );
    printFormat("cab", false, "read-only; stored, MSZIP and LZX folders; no multi-cabinet sets");
    printFormat(
        "wim",
        false,
        "read-only; stored and lzx resources, multi-image via --image; no xpress or lzms"
    );
    printFormat("iso", false, "read-only; ISO9660 with Rock Ridge, Joliet and El Torito");
    printFormat("gzip", false, "one compressed file, multi-member; named by FNAME or archive name");
    printFormat("zstd", false, "one compressed file, multi-frame, window up to 128 MiB");
    printFormat("xz", false, "one compressed file, multi-stream; memory capped at 256 MiB");
    printFormat("bzip2", false, "one compressed file, multi-stream; read as one stream");
    printFormat(
        "bale",
        true,
        "native format, raw, zstd, lz4, lzma2 and brotli chunks, presets; not frozen"
    );
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
    if (command == "convert") {
        return runConvert(rest);
    }
    if (command == "info") {
        std::optional<std::string> keyFile;
        bale::cli::VerifyKeys verifyKeys;
        std::string_view archive;
        for (std::size_t index = 0; index < rest.size(); ++index) {
            if (rest[index] == "--key-file") {
                if (index + 1 == rest.size()) {
                    return usageError("--key-file needs a path");
                }
                keyFile = std::string(rest[++index]);
                continue;
            }
            if (rest[index] == "--verify-key") {
                if (index + 1 == rest.size()) {
                    return usageError("--verify-key needs a key");
                }
                ++index;
                auto parsed = bale::cli::parseVerifyKey(rest[index]);
                if (!parsed) {
                    return usageError("invalid --verify-key");
                }
                verifyKeys.push_back(*parsed);
                continue;
            }
            if (rest[index].starts_with('-') || !archive.empty()) {
                return usageError("info takes exactly one archive and --key-file");
            }
            archive = rest[index];
        }
        if (archive.empty()) {
            return usageError("info takes exactly one archive");
        }
        return exitWith(bale::cli::describeArchive(archive, keyFile, verifyKeys));
    }
    if (command == "history") {
        return runHistory(rest);
    }
    if (command == "test") {
        return runTest(rest);
    }
    if (command == "repair") {
        return runRepair(rest);
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
