#include "archive/chunk.hpp"
#include "codecs/decoders.hpp"
#include "codecs/deflate_encoder.hpp"
#include "codecs/zstd_encoder.hpp"
#include "format/record.hpp"
#include "io/file.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

#ifdef _WIN32
#include <windows.h>

#include <psapi.h>
#else
#include <sys/resource.h>
#endif

using namespace bale;

namespace {

enum class CodecKind : std::uint8_t {
    Raw,
    Zstd,
    Deflate,
};

struct CodecSpec {
    CodecKind kind = CodecKind::Raw;
    int level = 0;
    std::string label;
};

struct ChunkRange {
    std::size_t offset = 0;
    std::size_t length = 0;
};

struct Group {
    std::string name;
    std::vector<std::byte> data;
    std::vector<ChunkRange> chunks;
    std::uint64_t files = 0;
};

struct Options {
    std::filesystem::path corpus;
    std::size_t chunkSize = archive::defaultChunkSize;
    int runs = 5;
    std::vector<CodecSpec> codecs;
};

struct Spread {
    double median = 0;
    double min = 0;
    double max = 0;
};

struct Measurement {
    std::uint64_t storedBytes = 0;
    std::uint64_t rawFallbackChunks = 0;
    Spread encodeMegabytesPerSecond;
    Spread decodeMegabytesPerSecond;
};

struct RawCodec {};

struct ZstdCodec {
    ZstdEncoder encoder;
    ZstdDecoder decoder;
};

struct DeflateCodec {
    DeflateEncoder encoder;
    Inflater decoder;
};

using Codec = std::variant<RawCodec, ZstdCodec, DeflateCodec>;

std::optional<Codec> createCodec(const CodecSpec& spec) {
    if (spec.kind == CodecKind::Zstd) {
        auto encoder = ZstdEncoder::create(spec.level);
        auto decoder = ZstdDecoder::create();
        if (!encoder || !decoder) {
            return std::nullopt;
        }
        return Codec{ZstdCodec{
            .encoder = std::move(*encoder),
            .decoder = std::move(*decoder),
        }};
    }
    if (spec.kind == CodecKind::Deflate) {
        auto encoder = DeflateEncoder::create(spec.level);
        auto decoder = Inflater::create();
        if (!encoder || !decoder) {
            return std::nullopt;
        }
        return Codec{DeflateCodec{
            .encoder = std::move(*encoder),
            .decoder = std::move(*decoder),
        }};
    }
    return Codec{RawCodec{}};
}

std::size_t boundOf(const Codec& codec, std::size_t size) {
    if (std::holds_alternative<ZstdCodec>(codec)) {
        return ZstdEncoder::compressBound(size);
    }
    if (std::holds_alternative<DeflateCodec>(codec)) {
        return DeflateEncoder::compressBound(size);
    }
    return size;
}

std::optional<std::size_t>
encodeChunk(Codec& codec, std::span<const std::byte> input, std::span<std::byte> output) {
    Result<std::size_t> size = input.size();
    if (auto* zstd = std::get_if<ZstdCodec>(&codec)) {
        size = zstd->encoder.compress(input, output);
    } else if (auto* deflate = std::get_if<DeflateCodec>(&codec)) {
        size = deflate->encoder.compress(input, output);
    } else {
        std::memcpy(output.data(), input.data(), input.size());
    }
    if (!size) {
        return std::nullopt;
    }
    return *size;
}

template <typename Decoder>
bool decodeWhole(Decoder& decoder, std::span<const std::byte> input, std::span<std::byte> output) {
    std::size_t produced = 0;
    while (true) {
        auto step = decoder.decompress(input, output.subspan(produced));
        if (!step) {
            return false;
        }

        input = input.subspan(step->consumed);
        produced += step->produced;
        if (step->finished) {
            break;
        }
        if (step->consumed == 0 && step->produced == 0) {
            return false;
        }
    }
    return decoder.reset().has_value() && produced == output.size();
}

bool decodeChunk(Codec& codec, std::span<const std::byte> input, std::span<std::byte> output) {
    if (auto* zstd = std::get_if<ZstdCodec>(&codec)) {
        return decodeWhole(zstd->decoder, input, output);
    }
    if (auto* deflate = std::get_if<DeflateCodec>(&codec)) {
        return decodeWhole(deflate->decoder, input, output);
    }
    std::memcpy(output.data(), input.data(), input.size());
    return input.size() == output.size();
}

std::optional<CodecSpec> parseCodec(std::string_view text) {
    if (text == "raw") {
        return CodecSpec{
            .kind = CodecKind::Raw,
            .level = 0,
            .label = "raw",
        };
    }

    auto colon = text.find(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }
    std::string_view name = text.substr(0, colon);
    std::string_view levelText = text.substr(colon + 1);
    int level = 0;
    auto [end, error] =
        std::from_chars(levelText.data(), levelText.data() + levelText.size(), level);
    if (error != std::errc{} || end != levelText.data() + levelText.size()) {
        return std::nullopt;
    }

    CodecSpec spec;
    spec.level = level;
    spec.label = std::string(text);
    if (name == "zstd") {
        spec.kind = CodecKind::Zstd;
        return spec;
    }
    if (name == "deflate") {
        spec.kind = CodecKind::Deflate;
        return spec;
    }
    return std::nullopt;
}

std::optional<Options> parseOptions(std::span<char*> arguments) {
    Options options;
    for (std::size_t index = 1; index < arguments.size(); ++index) {
        std::string_view argument = arguments[index];
        bool hasValue = index + 1 < arguments.size();
        if (argument == "--chunk-size" && hasValue) {
            ++index;
            std::string_view value = arguments[index];
            auto [end, error] =
                std::from_chars(value.data(), value.data() + value.size(), options.chunkSize);
            if (error != std::errc{} || options.chunkSize < archive::minChunkSize ||
                options.chunkSize > archive::maxChunkSize) {
                return std::nullopt;
            }
            continue;
        }
        if (argument == "--runs" && hasValue) {
            ++index;
            std::string_view value = arguments[index];
            auto [end, error] =
                std::from_chars(value.data(), value.data() + value.size(), options.runs);
            if (error != std::errc{} || options.runs < 1) {
                return std::nullopt;
            }
            continue;
        }
        if (argument == "--codec" && hasValue) {
            ++index;
            auto spec = parseCodec(arguments[index]);
            if (!spec) {
                return std::nullopt;
            }
            options.codecs.push_back(*spec);
            continue;
        }
        if (argument.starts_with('-') || !options.corpus.empty()) {
            return std::nullopt;
        }
        options.corpus = std::filesystem::path(argument);
    }

    if (options.corpus.empty()) {
        return std::nullopt;
    }
    if (options.codecs.empty()) {
        constexpr std::array defaults{
            std::string_view{"raw"},
            std::string_view{"zstd:1"},
            std::string_view{"zstd:3"},
            std::string_view{"zstd:9"},
            std::string_view{"zstd:19"},
            std::string_view{"deflate:1"},
            std::string_view{"deflate:6"},
            std::string_view{"deflate:9"},
        };
        for (std::string_view text : defaults) {
            if (auto spec = parseCodec(text)) {
                options.codecs.push_back(*spec);
            }
        }
    }
    return options;
}

bool appendFile(const std::filesystem::path& path, std::size_t chunkSize, Group& group) {
    auto file = File::openRegularNoFollow(path);
    if (!file) {
        return false;
    }
    auto size = file->size();
    if (!size) {
        return false;
    }

    std::size_t start = group.data.size();
    group.data.resize(start + static_cast<std::size_t>(*size));
    auto read = file->readExactAt(0, std::span(group.data).subspan(start));
    if (!read) {
        return false;
    }

    for (std::size_t offset = start; offset < group.data.size(); offset += chunkSize) {
        group.chunks.push_back(
            ChunkRange{
                .offset = offset,
                .length = std::min(chunkSize, group.data.size() - offset),
            }
        );
    }
    ++group.files;
    return true;
}

std::vector<Group> loadCorpus(const Options& options) {
    std::vector<std::filesystem::path> groupPaths;
    std::error_code error;
    for (const auto& item : std::filesystem::directory_iterator(options.corpus, error)) {
        if (item.is_directory(error) && !item.is_symlink(error)) {
            groupPaths.push_back(item.path());
        }
    }
    std::ranges::sort(groupPaths);

    std::vector<Group> groups;
    for (const auto& groupPath : groupPaths) {
        std::vector<std::filesystem::path> files;
        std::filesystem::recursive_directory_iterator walk(groupPath, error);
        std::filesystem::recursive_directory_iterator end;
        for (auto it = walk; !error && it != end; it.increment(error)) {
            if (it->is_regular_file(error) && !it->is_symlink(error)) {
                files.push_back(it->path());
            }
        }
        std::ranges::sort(files);

        Group& group = groups.emplace_back();
        group.name = groupPath.filename().string();
        for (const auto& path : files) {
            if (!appendFile(path, options.chunkSize, group)) {
                std::println(stderr, "skipping unreadable file {}", path.string());
            }
        }
    }
    return groups;
}

std::uint64_t recordOverhead(std::size_t chunkLength) {
    archive::ChunkKey key;
    key.length = chunkLength;
    std::vector<std::byte> descriptor;
    if (!archive::encodeDataDescriptor(key, descriptor)) {
        return recordFramingSize;
    }
    return recordFramingSize + descriptor.size();
}

Spread spreadOf(std::vector<double> samples) {
    std::ranges::sort(samples);
    return Spread{
        .median = samples[samples.size() / 2],
        .min = samples.front(),
        .max = samples.back(),
    };
}

std::optional<Measurement>
measure(const Options& options, const CodecSpec& spec, const Group& group) {
    auto created = createCodec(spec);
    if (!created) {
        return std::nullopt;
    }
    Codec& codec = *created;

    std::vector<std::size_t> encodedOffsets(group.chunks.size());
    std::vector<std::size_t> encodedSizes(group.chunks.size());
    std::size_t arenaSize = 0;
    for (std::size_t index = 0; index < group.chunks.size(); ++index) {
        encodedOffsets[index] = arenaSize;
        arenaSize += boundOf(codec, group.chunks[index].length);
    }
    std::vector<std::byte> arena(arenaSize);
    std::vector<std::byte> decoded(options.chunkSize);

    Measurement result;
    std::vector<double> encodeSamples;
    std::vector<double> decodeSamples;
    const double megabytes = static_cast<double>(group.data.size()) / 1e6;
    for (int run = 0; run < options.runs; ++run) {
        auto encodeStart = std::chrono::steady_clock::now();
        for (std::size_t index = 0; index < group.chunks.size(); ++index) {
            const ChunkRange& range = group.chunks[index];
            auto input = std::span(group.data).subspan(range.offset, range.length);
            auto output =
                std::span(arena).subspan(encodedOffsets[index], boundOf(codec, range.length));
            auto size = encodeChunk(codec, input, output);
            if (!size) {
                return std::nullopt;
            }
            encodedSizes[index] = *size;
        }
        std::chrono::duration<double> encodeTime = std::chrono::steady_clock::now() - encodeStart;

        auto decodeStart = std::chrono::steady_clock::now();
        for (std::size_t index = 0; index < group.chunks.size(); ++index) {
            const ChunkRange& range = group.chunks[index];
            if (encodedSizes[index] >= range.length) {
                std::memcpy(decoded.data(), group.data.data() + range.offset, range.length);
                continue;
            }
            auto input = std::span(arena).subspan(encodedOffsets[index], encodedSizes[index]);
            if (!decodeChunk(codec, input, std::span(decoded).first(range.length))) {
                return std::nullopt;
            }
            bool mismatch =
                std::memcmp(decoded.data(), group.data.data() + range.offset, range.length) != 0;
            if (run == 0 && mismatch) {
                return std::nullopt;
            }
        }
        std::chrono::duration<double> decodeTime = std::chrono::steady_clock::now() - decodeStart;

        encodeSamples.push_back(megabytes / encodeTime.count());
        decodeSamples.push_back(megabytes / std::max(decodeTime.count(), 1e-9));
    }

    for (std::size_t index = 0; index < group.chunks.size(); ++index) {
        std::size_t length = group.chunks[index].length;
        bool fallback = encodedSizes[index] >= length;
        result.rawFallbackChunks += fallback ? 1 : 0;
        result.storedBytes += (fallback ? length : encodedSizes[index]) + recordOverhead(length);
    }
    result.encodeMegabytesPerSecond = spreadOf(encodeSamples);
    result.decodeMegabytesPerSecond = spreadOf(decodeSamples);
    return result;
}

std::uint64_t peakResidentKilobytes() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS counters{};
    if (!GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters))) {
        return 0;
    }
    return counters.PeakWorkingSetSize / 1024;
#else
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return 0;
    }
#ifdef __APPLE__
    return static_cast<std::uint64_t>(usage.ru_maxrss) / 1024;
#else
    return static_cast<std::uint64_t>(usage.ru_maxrss);
#endif
#endif
}

std::string jsonString(std::string_view text) {
    std::string out = "\"";
    for (char c : text) {
        auto byte = static_cast<unsigned char>(c);
        if (c == '"' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (byte < 0x20) {
            out += std::format("\\u{:04x}", byte);
        } else {
            out.push_back(c);
        }
    }
    out.push_back('"');
    return out;
}

std::string jsonSpread(const Spread& spread) {
    return std::format(
        "{{\"median\":{:.2f},\"min\":{:.2f},\"max\":{:.2f}}}",
        spread.median,
        spread.min,
        spread.max
    );
}

int run(std::span<char*> arguments) {
    auto options = parseOptions(arguments);
    if (!options) {
        std::println(
            stderr,
            "usage: bale_bench_codecs <corpus> [--chunk-size N] [--runs N] "
            "[--codec raw|zstd:L|deflate:L]..."
        );
        return 2;
    }

    auto groups = loadCorpus(*options);
    if (groups.empty()) {
        std::println(stderr, "no group directories found in the corpus");
        return 2;
    }

    std::println(
        stderr,
        "{:<12} {:<14} {:>14} {:>14} {:>8} {:>26} {:>26}",
        "codec",
        "group",
        "input",
        "stored",
        "ratio",
        "encode MB/s med [min-max]",
        "decode MB/s med [min-max]"
    );
    for (const CodecSpec& spec : options->codecs) {
        for (const Group& group : groups) {
            auto measured = measure(*options, spec, group);
            if (!measured) {
                std::println(
                    stderr,
                    "{}: {} failed to encode, decode or round-trip",
                    spec.label,
                    group.name
                );
                return 1;
            }

            double ratio = 0;
            if (!group.data.empty()) {
                ratio = static_cast<double>(measured->storedBytes) /
                    static_cast<double>(group.data.size());
            }
            std::println(
                "{{\"codec\":{},\"group\":{},\"files\":{},\"chunks\":{},\"chunk_size\":{},"
                "\"runs\":{},\"input_bytes\":{},\"stored_bytes\":{},\"raw_fallback_chunks\":{},"
                "\"encode_mb_s\":{},\"decode_mb_s\":{}}}",
                jsonString(spec.label),
                jsonString(group.name),
                group.files,
                group.chunks.size(),
                options->chunkSize,
                options->runs,
                group.data.size(),
                measured->storedBytes,
                measured->rawFallbackChunks,
                jsonSpread(measured->encodeMegabytesPerSecond),
                jsonSpread(measured->decodeMegabytesPerSecond)
            );
            std::println(
                stderr,
                "{:<12} {:<14} {:>14} {:>14} {:>8.4f} {:>8.1f} [{:.1f}-{:.1f}] {:>8.1f} "
                "[{:.1f}-{:.1f}]",
                spec.label,
                group.name,
                group.data.size(),
                measured->storedBytes,
                ratio,
                measured->encodeMegabytesPerSecond.median,
                measured->encodeMegabytesPerSecond.min,
                measured->encodeMegabytesPerSecond.max,
                measured->decodeMegabytesPerSecond.median,
                measured->decodeMegabytesPerSecond.min,
                measured->decodeMegabytesPerSecond.max
            );
        }
    }

    std::println("{{\"peak_rss_kb\":{}}}", peakResidentKilobytes());
    return 0;
}

}

int main(int argc, char** argv) {
    try {
        return run(std::span(argv, static_cast<std::size_t>(argc)));
    } catch (const std::exception& error) {
        std::fputs(error.what(), stderr);
        std::fputs("\n", stderr);
        return 1;
    }
}
