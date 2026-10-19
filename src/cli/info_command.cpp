#include "archive/reader.hpp"
#include "archive/writer_profile.hpp"
#include "cli/archive_commands.hpp"
#include "cli/terminal_text.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <print>
#include <string>
#include <utility>

namespace bale::cli {

namespace {

void printPreset(std::uint64_t value) {
    for (archive::Preset preset : archive::allPresets) {
        if (static_cast<std::uint64_t>(preset) == value) {
            std::println("preset: {}", archive::presetName(preset));
            return;
        }
    }
    std::println("preset: unknown ({})", value);
}

void printCodec(std::uint64_t value, std::optional<std::int64_t> level) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        std::println("codec: unknown ({})", value);
        return;
    }

    auto codec = static_cast<CodecId>(value);
    std::string_view name = codecName(codec);
    if (!level || codec == CodecId::Raw) {
        std::println("codec: {}", name);
        return;
    }
    std::println("codec: {} level {}", name, *level);
}

void printChunking(const archive::WriterMetadata& writer) {
    std::string_view policy = "unknown";
    if (writer.chunkPolicy == static_cast<std::uint64_t>(archive::ChunkPolicy::Fixed)) {
        policy = "fixed";
    }
    if (writer.chunkPolicy == static_cast<std::uint64_t>(archive::ChunkPolicy::Cdc)) {
        policy = "cdc";
    }

    if (policy == "cdc" && writer.chunkMin && writer.chunkTarget && writer.chunkMax) {
        std::println(
            "chunking: {}, min {} target {} max {} bytes",
            policy,
            *writer.chunkMin,
            *writer.chunkTarget,
            *writer.chunkMax
        );
        return;
    }
    if (writer.chunkSize) {
        std::println("chunking: {}, {} bytes", policy, *writer.chunkSize);
        return;
    }
    std::println("chunking: {}", policy);
}

void printWriter(const archive::WriterMetadata& writer) {
    if (writer.empty()) {
        std::println("writer: not recorded");
        return;
    }

    std::string escaped;
    if (!writer.name.empty()) {
        std::println("writer: {}", escapeForTerminal(writer.name, escaped));
    }
    if (writer.preset) {
        printPreset(*writer.preset);
    }
    if (writer.codec) {
        printCodec(*writer.codec, writer.level);
    }
    if (writer.chunkPolicy || writer.chunkSize) {
        printChunking(writer);
    }
    if (writer.workers) {
        std::println("workers: {}", *writer.workers);
    }
}

ExitCode describeNative(std::string_view argument, File file) {
    auto reader = archive::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::uint64_t storedBytes = 0;
    for (const archive::IndexEntry& entry : reader->index()) {
        storedBytes += entry.recordLength;
    }

    std::println("format: bale");
    std::println("generation: {}", reader->commit().generation);
    std::println("entries: {}", reader->manifest().entries.size());
    std::println("chunks: {} in {} stored bytes", reader->index().size(), storedBytes);
    printWriter(reader->manifest().writer);
    return ExitCode::Ok;
}

}

ExitCode describeArchive(std::string_view argument) {
    auto archive = openArchive(argument);
    if (!archive) {
        return reportFailure(argument, archive.error());
    }

    if (archive->format.container == Container::Bale) {
        return describeNative(argument, std::move(archive->file));
    }
    std::println("format: {}", name(archive->format));
    return ExitCode::Ok;
}

}
