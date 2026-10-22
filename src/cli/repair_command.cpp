#include "archive/parity_repair.hpp"

#include "archive/encrypted.hpp"
#include "archive/reader.hpp"
#include "cli/archive_commands.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/terminal_text.hpp"
#include "cli/unlock.hpp"

#include <filesystem>
#include <print>
#include <utility>

namespace bale::cli {

ExitCode repairArchive(
    std::string_view archivePath,
    const std::optional<std::string>& keyFile,
    const VerifyKeys& verifyKeys
) {
    archive::RepairOutcome outcome;
    {
        auto file = File::openReadWrite(pathFromUtf8(archivePath));
        if (!file) {
            return reportFailure(archivePath, file.error());
        }
        auto size = file->size();
        if (!size) {
            return reportFailure(archivePath, size.error());
        }
        std::array<std::byte, superblockSize> block{};
        if (auto read = file->readExactAt(0, block); !read) {
            return reportFailure(archivePath, read.error());
        }
        auto superblock = decodeSuperblock(block);
        if (!superblock) {
            return reportFailure(archivePath, superblock.error());
        }

        bool encrypted = (superblock->requiredFeatures & encryptedRequiredFeature) != 0;
        std::optional<archive::RepairKeys> keys;
        if (encrypted) {
            auto unlock = buildUnlock(keyFile, true);
            if (!unlock) {
                return reportFailure(archivePath, unlock.error());
            }
            auto found =
                archive::collectDataKeys(*file, *size, *unlock, archive::ReaderOptions{}.limits);
            if (!found) {
                return reportFailure(archivePath, found.error());
            }
            if (found->empty()) {
                return reportFailure(
                    archivePath,
                    Error{
                        .kind = ErrorKind::PasswordRequired,
                        .what = "no keyslot could be unlocked"
                    }
                );
            }
            archive::RepairKeys repairKeys;
            repairKeys.byEpoch = std::move(*found);
            repairKeys.archiveId = superblock->archiveId;
            keys.emplace(std::move(repairKeys));
        }

        auto repaired = archive::repairParityGenerations(
            *file,
            *size,
            *superblock,
            Limits{},
            keys ? &*keys : nullptr
        );
        if (!repaired) {
            return reportFailure(archivePath, repaired.error());
        }
        outcome = std::move(*repaired);
    }
    if (outcome.generations.empty()) {
        std::println("no parity generations in {}", archivePath);
    }
    for (const auto& generation : outcome.generations) {
        if (generation.repaired) {
            std::println(
                "generation {}: repaired {} bytes ({} parity records rebuilt){}",
                generation.generation,
                generation.repairedBytes,
                generation.repairedRecords,
                generation.note.empty() ? "" : std::string(" (") + generation.note + ")"
            );
        } else if (generation.note.empty()) {
            std::println("generation {}: no errors found", generation.generation);
        } else {
            std::println("generation {}: not repaired: {}", generation.generation, generation.note);
        }
    }

    auto reader = archive::Reader::open(*File::openRead(pathFromUtf8(archivePath)));
    std::optional<archive::Reader> encryptedReader;
    if (!reader && reader.error().kind == ErrorKind::PasswordRequired) {
        auto unlock = buildUnlock(keyFile, true);
        if (!unlock) {
            return reportFailure(archivePath, unlock.error());
        }
        auto retry = File::openRead(pathFromUtf8(archivePath));
        if (!retry) {
            return reportFailure(archivePath, retry.error());
        }
        auto opened = archive::Reader::openEncrypted(
            std::move(*retry),
            archive::ReaderOptions{},
            std::move(*unlock)
        );
        if (!opened) {
            return reportFailure(archivePath, opened.error());
        }
        encryptedReader.emplace(std::move(*opened));
    } else if (!reader) {
        return reportFailure(archivePath, reader.error());
    }
    archive::Reader& active = encryptedReader ? *encryptedReader : *reader;

    if (auto signed_ = requireSignatures(active, verifyKeys); !signed_) {
        return reportFailure(archivePath, signed_.error());
    }
    auto report = active.verify(archive::VerifyMode::Content);
    if (!report) {
        return reportFailure(archivePath, report.error());
    }
    std::println(
        "ok: {} entries, {} chunks ({} bytes) match their BLAKE3 digests",
        active.manifest().entries.size(),
        report->chunksVerified,
        report->bytesVerified
    );
    return ExitCode::Ok;
}

}
