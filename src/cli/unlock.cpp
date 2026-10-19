#include "cli/unlock.hpp"

#include "cli/filesystem_path.hpp"
#include "cli/prompt.hpp"

#include <sodium/utils.h>

#include <charconv>
#include <fstream>
#include <string>

namespace bale::cli {

namespace {

int hexValue(char digit) {
    if (digit >= '0' && digit <= '9') {
        return digit - '0';
    }
    if (digit >= 'a' && digit <= 'f') {
        return digit - 'a' + 10;
    }
    if (digit >= 'A' && digit <= 'F') {
        return digit - 'A' + 10;
    }
    return -1;
}

}

Result<std::array<std::byte, 32>> parseRecipientHex(std::string_view text) {
    if (text.size() != 64) {
        return fail(ErrorKind::Malformed, "recipient key must be 64 hex characters");
    }
    std::array<std::byte, 32> out{};
    for (std::size_t index = 0; index < 32; ++index) {
        int high = hexValue(text[index * 2]);
        int low = hexValue(text[index * 2 + 1]);
        if (high < 0 || low < 0) {
            return fail(ErrorKind::Malformed, "recipient key is not hex");
        }
        out[index] = static_cast<std::byte>((high << 4) | low);
    }
    return out;
}

Result<archive::ReaderUnlock>
buildUnlock(const std::optional<std::string>& keyFile, bool promptIfNeeded) {
    archive::ReaderUnlock unlock;
    if (keyFile) {
        std::ifstream input(*keyFile);
        if (!input) {
            return fail(ErrorKind::Io, "cannot open key file");
        }
        std::string line;
        while (std::getline(input, line)) {
            while (!line.empty() &&
                   (line.back() == '\n' || line.back() == '\r' || line.back() == ' ' ||
                    line.back() == '\t')) {
                line.pop_back();
            }
            std::size_t start = 0;
            while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) {
                ++start;
            }
            if (start >= line.size() || line[start] == '#') {
                sodium_memzero(line.data(), line.size());
                line.clear();
                continue;
            }
            std::string_view hex(line.data() + start, line.size() - start);
            if (hex.size() != 64) {
                // NOTE: wipe the line even on this early return; it holds key material.
                sodium_memzero(line.data(), line.size());
                return fail(ErrorKind::Malformed, "key file must hold 64 hex characters per line");
            }
            auto secretBytes = parseRecipientHex(hex);
            // NOTE: parseRecipientHex validates hex; reuse its bytes as the secret.
            if (!secretBytes) {
                return std::unexpected(secretBytes.error());
            }
            auto made = crypto::SecretBytes::make(32);
            if (!made) {
                return std::unexpected(made.error());
            }
            crypto::SecretBytes secret(std::move(*made));
            std::ranges::copy(*secretBytes, secret.mut().begin());
            sodium_memzero(secretBytes->data(), secretBytes->size());
            auto pub = crypto::publicKeyOf(secret.bytes());
            if (!pub) {
                return std::unexpected(pub.error());
            }
            archive::ReaderUnlock::RecipientKey key;
            key.publicKey = *pub;
            key.secretKey = std::move(secret);
            unlock.recipients.push_back(std::move(key));
            sodium_memzero(line.data(), line.size());
            line.clear();
        }
        if (unlock.recipients.empty()) {
            return fail(ErrorKind::Malformed, "key file holds no keys");
        }
        if (unlock.recipients.size() > 64) {
            return fail(ErrorKind::LimitExceeded, "too many keys in key file");
        }
    }
    if (promptIfNeeded && unlock.recipients.empty()) {
        auto password = promptPassword("bale password: ");
        if (!password) {
            return std::unexpected(password.error());
        }
        unlock.hasPassword = true;
        unlock.password = std::move(*password);
    }
    return unlock;
}

}
