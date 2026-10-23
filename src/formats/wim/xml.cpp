#include "formats/wim/xml.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"

#include <array>

namespace bale::wim {

namespace {

inline constexpr std::uint64_t bom = 0xFEFF;

struct Cursor {
    const std::byte* data = nullptr;
    std::size_t units = 0;
    std::size_t at = 0;

    [[nodiscard]] bool done() const {
        return at >= units;
    }

    [[nodiscard]] std::uint16_t peek() const {
        return loadLe<std::uint16_t>(data + at * 2);
    }

    void skip(std::size_t count) {
        at += count;
    }
};

[[nodiscard]] bool consume(Cursor& cursor, std::string_view ascii) {
    if (cursor.at + ascii.size() > cursor.units) {
        return false;
    }
    for (std::size_t index = 0; index < ascii.size(); ++index) {
        if (cursor.data[(cursor.at + index) * 2] != static_cast<std::byte>(ascii[index]) ||
            cursor.data[(cursor.at + index) * 2 + 1] != std::byte{0}) {
            return false;
        }
    }
    cursor.at += ascii.size();
    return true;
}

[[nodiscard]] bool consumeUnit(Cursor& cursor, std::uint16_t unit) {
    if (cursor.done() || cursor.peek() != unit) {
        return false;
    }
    cursor.skip(1);
    return true;
}

void skipWhitespace(Cursor& cursor) {
    while (!cursor.done()) {
        std::uint16_t unit = cursor.peek();
        if (unit != ' ' && unit != '\t' && unit != '\n' && unit != '\r') {
            return;
        }
        cursor.skip(1);
    }
}

[[nodiscard]] Result<std::uint32_t> parseDigits(Cursor& cursor, std::uint64_t offset) {
    std::uint64_t value = 0;
    std::size_t digits = 0;
    while (!cursor.done()) {
        std::uint16_t unit = cursor.peek();
        if (unit < '0' || unit > '9') {
            break;
        }
        value = value * 10 + (unit - '0');
        if (value > 0xFFFFFFFFULL) {
            return fail(ErrorKind::Malformed, "WIM image index is out of range", offset);
        }
        cursor.skip(1);
        ++digits;
    }
    if (digits == 0) {
        return fail(ErrorKind::Malformed, "WIM image index is missing", offset);
    }
    return static_cast<std::uint32_t>(value);
}

[[nodiscard]] Result<void> appendUnit(std::string& out, std::uint16_t first, Cursor& cursor) {
    if (first < 0x80) {
        if (first == 0) {
            return fail(ErrorKind::Malformed, "WIM name contains NUL");
        }
        out.push_back(static_cast<char>(first));
    } else if (first < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (first >> 6)));
        out.push_back(static_cast<char>(0x80 | (first & 0x3F)));
    } else if (first < 0xD800 || first >= 0xE000) {
        out.push_back(static_cast<char>(0xE0 | (first >> 12)));
        out.push_back(static_cast<char>(0x80 | ((first >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (first & 0x3F)));
    } else {
        if (cursor.done()) {
            return fail(ErrorKind::Malformed, "WIM name ends inside a surrogate pair");
        }
        std::uint16_t second = cursor.peek();
        if (second < 0xDC00 || second >= 0xE000) {
            return fail(ErrorKind::Malformed, "WIM name has a lone surrogate");
        }
        cursor.skip(1);
        char32_t point =
            (static_cast<char32_t>(first - 0xD800) << 10) + (second - 0xDC00) + 0x10000;
        out.push_back(static_cast<char>(0xF0 | (point >> 18)));
        out.push_back(static_cast<char>(0x80 | ((point >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (point & 0x3F)));
    }
    return {};
}

[[nodiscard]] Result<std::string> parseText(Cursor& cursor, const Limits& limits) {
    std::string out;
    while (!cursor.done()) {
        if (cursor.peek() == '<') {
            return out;
        }
        if (cursor.peek() == '&') {
            cursor.skip(1);
            if (consume(cursor, "amp;")) {
                out.push_back('&');
            } else if (consume(cursor, "lt;")) {
                out.push_back('<');
            } else if (consume(cursor, "gt;")) {
                out.push_back('>');
            } else if (consume(cursor, "quot;")) {
                out.push_back('"');
            } else if (consume(cursor, "apos;")) {
                out.push_back('\'');
            } else {
                return fail(ErrorKind::Malformed, "WIM XML has an unknown entity");
            }
            continue;
        }
        std::uint16_t unit = cursor.peek();
        cursor.skip(1);
        auto appended = appendUnit(out, unit, cursor);
        if (!appended) {
            return tl::unexpected<Error>(appended.error());
        }
        if (out.size() > limits.maxNameBytes * 4) {
            return fail(ErrorKind::LimitExceeded, "WIM image name exceeds limit");
        }
    }
    return fail(ErrorKind::Truncated, "WIM XML ends inside text");
}

void skipText(Cursor& cursor) {
    while (!cursor.done() && cursor.peek() != '<') {
        cursor.skip(1);
    }
}

[[nodiscard]] Result<bool> skipElement(Cursor& cursor) {
    if (!consumeUnit(cursor, '<')) {
        return fail(ErrorKind::Malformed, "WIM XML is malformed");
    }
    if (consumeUnit(cursor, '?')) {
        while (!cursor.done()) {
            if (consume(cursor, "?>")) {
                return true;
            }
            cursor.skip(1);
        }
        return fail(ErrorKind::Truncated, "WIM XML ends inside a directive");
    }
    if (consume(cursor, "!--")) {
        while (!cursor.done()) {
            if (consume(cursor, "-->")) {
                return true;
            }
            cursor.skip(1);
        }
        return fail(ErrorKind::Truncated, "WIM XML ends inside a comment");
    }
    if (consume(cursor, "![CDATA[")) {
        while (!cursor.done()) {
            if (consume(cursor, "]]>")) {
                return true;
            }
            cursor.skip(1);
        }
        return fail(ErrorKind::Truncated, "WIM XML ends inside CDATA");
    }
    bool closing = consumeUnit(cursor, '/');
    while (!cursor.done() && cursor.peek() != '>') {
        cursor.skip(1);
    }
    if (cursor.done()) {
        return fail(ErrorKind::Truncated, "WIM XML ends inside a tag");
    }
    cursor.skip(1);
    return closing;
}

}

Result<std::vector<ImageInfo>>
parseImageList(const File& file, const Header& header, const Limits& limits) {
    if (header.imageCount > limits.maxImages) {
        return fail(ErrorKind::LimitExceeded, "WIM image count exceeds limit");
    }
    if ((header.xml.flags & resFlagCompressed) != 0) {
        return fail(
            ErrorKind::Unsupported,
            "compressed WIM metadata XML is not supported",
            header.xml.offset
        );
    }
    if (header.xml.sizeInWim != header.xml.uncompressed) {
        return fail(ErrorKind::Malformed, "WIM metadata XML size mismatch", header.xml.offset);
    }
    if (header.xml.sizeInWim > limits.maxXmlBytes) {
        return fail(ErrorKind::LimitExceeded, "WIM metadata XML exceeds limit");
    }
    if (header.xml.sizeInWim % 2 != 0) {
        return fail(ErrorKind::Malformed, "WIM metadata XML has an odd length");
    }
    std::size_t bytes = static_cast<std::size_t>(header.xml.sizeInWim);
    std::vector<std::byte> raw(bytes);
    auto read = file.readExactAt(header.xml.offset, std::span(raw));
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }

    Cursor cursor{.data = raw.data(), .units = bytes / 2, .at = 0};
    if (!cursor.done() && cursor.peek() == bom) {
        cursor.skip(1);
    }

    std::vector<ImageInfo> images;
    while (!cursor.done()) {
        skipWhitespace(cursor);
        if (cursor.done()) {
            break;
        }
        if (cursor.peek() != '<') {
            skipText(cursor);
            continue;
        }
        std::size_t mark = cursor.at;
        cursor.skip(1);
        if (consume(cursor, "IMAGE") &&
            (cursor.done() || cursor.peek() == ' ' || cursor.peek() == '\t' ||
             cursor.peek() == '\n' || cursor.peek() == '\r' || cursor.peek() == '>' ||
             cursor.peek() == '/')) {
            skipWhitespace(cursor);
            if (!consume(cursor, "INDEX")) {
                return fail(ErrorKind::Malformed, "WIM IMAGE tag has no index");
            }
            skipWhitespace(cursor);
            if (!consumeUnit(cursor, '=')) {
                return fail(ErrorKind::Malformed, "WIM IMAGE tag has no index");
            }
            skipWhitespace(cursor);
            if (!consumeUnit(cursor, '"')) {
                return fail(ErrorKind::Malformed, "WIM IMAGE tag has no index");
            }
            auto number = parseDigits(cursor, header.xml.offset);
            if (!number) {
                return tl::unexpected<Error>(number.error());
            }
            if (!consumeUnit(cursor, '"')) {
                return fail(ErrorKind::Malformed, "WIM IMAGE tag is not closed");
            }
            while (!cursor.done() && cursor.peek() != '>') {
                cursor.skip(1);
            }
            if (!consumeUnit(cursor, '>')) {
                return fail(ErrorKind::Truncated, "WIM XML ends inside IMAGE");
            }
            if (*number != images.size() + 1) {
                return fail(ErrorKind::Malformed, "WIM image indexes are not ordered");
            }
            ImageInfo image;
            bool closed = false;
            while (!cursor.done()) {
                if (cursor.peek() == '<') {
                    std::size_t body = cursor.at;
                    cursor.skip(1);
                    if (consume(cursor, "/IMAGE")) {
                        if (!consumeUnit(cursor, '>')) {
                            return fail(ErrorKind::Malformed, "WIM IMAGE tag is not closed");
                        }
                        closed = true;
                        break;
                    }
                    if (consume(cursor, "NAME") && !cursor.done() && cursor.peek() == '>') {
                        cursor.skip(1);
                        auto text = parseText(cursor, limits);
                        if (!text) {
                            return tl::unexpected<Error>(text.error());
                        }
                        if (!consumeUnit(cursor, '<') || !consume(cursor, "/NAME") ||
                            !consumeUnit(cursor, '>')) {
                            return fail(ErrorKind::Malformed, "WIM NAME tag is not closed");
                        }
                        if (text->empty() || text->size() > limits.maxNameBytes) {
                            return fail(ErrorKind::Malformed, "WIM image name is invalid");
                        }
                        image.name = std::move(*text);
                        continue;
                    }
                    cursor.at = body;
                    auto nested = skipElement(cursor);
                    if (!nested) {
                        return tl::unexpected<Error>(nested.error());
                    }
                    continue;
                }
                skipText(cursor);
            }
            if (!closed) {
                return fail(ErrorKind::Truncated, "WIM XML ends inside IMAGE");
            }
            if (image.name.empty()) {
                return fail(ErrorKind::Malformed, "WIM image has no name");
            }
            images.push_back(std::move(image));
            continue;
        }
        cursor.at = mark;
        auto skipped = skipElement(cursor);
        if (!skipped) {
            return tl::unexpected<Error>(skipped.error());
        }
    }

    if (images.size() != header.imageCount) {
        return fail(ErrorKind::Malformed, "WIM XML image count disagrees with its header");
    }
    return images;
}

}
