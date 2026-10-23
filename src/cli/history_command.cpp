#include "archive/reader.hpp"
#include "cli/archive_commands.hpp"
#include "cli/filesystem_path.hpp"
#include "cli/unlock.hpp"

#include <array>
#include <print>
#include <utility>

namespace bale::cli {

namespace {

std::array<char, 64> digestHex(const Blake3Digest& digest) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::array<char, 64> result{};
    std::size_t index = 0;
    for (std::byte value : digest) {
        const auto byte = static_cast<unsigned>(value);
        result[index++] = digits[byte >> 4];
        result[index++] = digits[byte & 0xF];
    }
    return result;
}

}

ExitCode historyArchive(
    std::string_view argument,
    const std::optional<std::string>& keyFile,
    const VerifyKeys& verifyKeys
) {
    auto file = File::openRead(pathFromUtf8(argument));
    if (!file) {
        return reportFailure(argument, file.error());
    }

    auto reader = archive::Reader::open(std::move(*file));
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
    if (auto verified = requireSignatures(active, verifyKeys); !verified) {
        return reportFailure(argument, verified.error());
    }

    const auto history = active.history();
    std::println("* marks the current snapshot");
    for (std::size_t index = history.size(); index > 0; --index) {
        const auto& generation = history[index - 1];
        const bool current = index == history.size();
        const auto digest = digestHex(generation.digest);
        std::println(
            "{} generation {}  epoch {}  commit {}",
            current ? '*' : ' ',
            generation.commit.generation,
            generation.commit.epoch,
            std::string_view(digest.data(), digest.size())
        );
    }
    return ExitCode::Ok;
}

}
