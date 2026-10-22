#include "archive/reader.hpp"
#include "archive/writer_profile.hpp"
#include "cli/archive_commands.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"
#include "cli/unlock.hpp"
#include "formats/wim/reader.hpp"

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

ExitCode describeNative(
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
    const archive::Reader& active = encrypted ? *encrypted : *reader;

    if (auto signed_ = requireSignatures(active, verifyKeys); !signed_) {
        return reportFailure(argument, signed_.error());
    }

    std::uint64_t storedBytes = 0;
    for (const archive::IndexEntry& entry : active.index()) {
        storedBytes += entry.recordLength;
    }

    std::println("format: bale");
    std::println("generation: {}", active.commit().generation);
    std::println("entries: {}", active.manifest().entries.size());
    std::println("chunks: {} in {} stored bytes", active.index().size(), storedBytes);
    if (active.encrypted()) {
        std::println("encryption: experimental XChaCha20-Poly1305, epoch {}", active.epoch());
    }
    if (active.parity().present) {
        std::println(
            "parity: experimental {}+{}, shard {} bytes, {} stripes",
            active.parity().dataShards,
            active.parity().parityShards,
            active.parity().shardBytes,
            active.parity().stripeCount
        );
    } else {
        std::println("parity: none");
    }
    if (active.hasSignatures()) {
        std::println(
            "signatures: {} covering generation {}",
            active.signatures().size(),
            active.commit().generation
        );
        for (const auto& signature : active.signatures()) {
            std::string hex;
            hex.reserve(signature.signer.size() * 2);
            constexpr std::string_view digits = "0123456789abcdef";
            for (std::byte value : signature.signer) {
                auto byte = static_cast<unsigned>(value);
                hex.push_back(digits[byte >> 4]);
                hex.push_back(digits[byte & 0xF]);
            }
            std::println("signer: {} epoch {}", hex, signature.epoch);
        }
    } else {
        std::println("signatures: none");
    }
    if (!verifyKeys.empty()) {
        std::println("signature: ok, signed by the verification key");
    }
    printWriter(active.manifest().writer);
    return ExitCode::Ok;
}

}

ExitCode describeWim(std::string_view argument, File file) {
    auto reader = wim::Reader::open(std::move(file));
    if (!reader) {
        return reportFailure(argument, reader.error());
    }

    std::println("format: wim");
    std::println("compression: {}", wim::compressionName(reader->compression()));
    std::println("images: {}", reader->images().size());
    if (reader->bootImage() == 0) {
        std::println("boot: none");
    } else {
        std::println("boot: {}", reader->bootImage());
    }
    std::string escaped;
    std::uint32_t index = 0;
    for (const auto& image : reader->images()) {
        ++index;
        std::println("image {}: {}", index, escapeForTerminal(image.name, escaped));
    }
    return ExitCode::Ok;
}

ExitCode describeArchive(
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

    if (archive->format.container == Container::Bale) {
        return describeNative(argument, std::move(archive->file), keyFile, verifyKeys);
    }
    if (archive->format.container == Container::Wim) {
        return describeWim(argument, std::move(archive->file));
    }
    std::println("format: {}", name(archive->format));
    return ExitCode::Ok;
}

}
