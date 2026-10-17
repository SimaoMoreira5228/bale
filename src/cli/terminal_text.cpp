#include "cli/terminal_text.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace bale::cli {

namespace {

struct CodePoint {
    std::uint32_t value = 0;
    std::size_t length = 0;
};

[[nodiscard]] std::optional<CodePoint> decodeUtf8(std::string_view text) {
    auto lead = static_cast<unsigned char>(text[0]);
    if (lead < 0x80) {
        return CodePoint{
            .value = lead,
            .length = 1,
        };
    }

    std::size_t length = 0;
    std::uint32_t value = 0;
    std::uint32_t minimum = 0;
    if (lead >= 0xC2 && lead < 0xE0) {
        length = 2;
        value = lead & 0x1FU;
        minimum = 0x80;
    } else if (lead >= 0xE0 && lead < 0xF0) {
        length = 3;
        value = lead & 0x0FU;
        minimum = 0x800;
    } else if (lead >= 0xF0 && lead < 0xF5) {
        length = 4;
        value = lead & 0x07U;
        minimum = 0x10000;
    } else {
        return std::nullopt;
    }

    if (text.size() < length) {
        return std::nullopt;
    }
    for (std::size_t index = 1; index < length; ++index) {
        auto byte = static_cast<unsigned char>(text[index]);
        if ((byte & 0xC0U) != 0x80) {
            return std::nullopt;
        }
        value = (value << 6) | (byte & 0x3FU);
    }

    if (value < minimum || value > 0x10FFFF || (value >= 0xD800 && value <= 0xDFFF)) {
        return std::nullopt;
    }
    return CodePoint{
        .value = value,
        .length = length,
    };
}

[[nodiscard]] bool needsEscape(std::uint32_t value) {
    bool control = value < 0x20 || (value >= 0x7F && value <= 0x9F);
    bool bidiEmbedding = value >= 0x202A && value <= 0x202E;
    bool bidiIsolate = value >= 0x2066 && value <= 0x2069;
    bool bidiMark = value == 0x200E || value == 0x200F || value == 0x061C;
    return control || bidiEmbedding || bidiIsolate || bidiMark;
}

void appendEscapedBytes(std::string& out, std::string_view bytes) {
    constexpr std::string_view digits = "0123456789abcdef";

    for (char c : bytes) {
        auto byte = static_cast<unsigned char>(c);
        out.append("\\x");
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 0x0FU]);
    }
}

}

std::string_view escapeForTerminal(std::string_view raw, std::string& buffer) {
    std::size_t position = 0;
    while (position < raw.size()) {
        auto decoded = decodeUtf8(raw.substr(position));
        if (!decoded || needsEscape(decoded->value) || raw[position] == '\\') {
            break;
        }
        position += decoded->length;
    }
    if (position == raw.size()) {
        return raw;
    }

    buffer.assign(raw.substr(0, position));
    while (position < raw.size()) {
        auto rest = raw.substr(position);
        auto decoded = decodeUtf8(rest);
        if (!decoded) {
            appendEscapedBytes(buffer, rest.substr(0, 1));
            ++position;
            continue;
        }

        auto sequence = rest.substr(0, decoded->length);
        if (needsEscape(decoded->value)) {
            appendEscapedBytes(buffer, sequence);
        } else if (sequence == "\\") {
            buffer.append("\\\\");
        } else {
            buffer.append(sequence);
        }
        position += decoded->length;
    }
    return buffer;
}

}
