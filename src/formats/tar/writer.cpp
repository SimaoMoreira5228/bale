#include "formats/tar/writer.hpp"

#include "base/checked.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <optional>

namespace bale::tar {

namespace {

constexpr std::uint64_t maxOctal8 = 07777777;
constexpr std::uint64_t maxOctal12 = 077777777777;
constexpr std::uint32_t permissionBits = 07777;
constexpr std::uint32_t paxHeaderMode = 0644;
constexpr std::string_view paxHeaderName = "././@PaxHeader";
constexpr std::array<std::byte, blockSize> zeroBlock{};

using HeaderBlock = std::array<std::byte, blockSize>;

bool isAscii(std::string_view text) {
    return std::ranges::all_of(text, [](char value) {
        return static_cast<unsigned char>(value) < 0x80;
    });
}

bool fitsText(std::string_view text, Field field) {
    return text.size() <= field.length && isAscii(text);
}

void putText(HeaderBlock& block, Field field, std::string_view text) {
    auto length = std::min(text.size(), field.length);
    for (std::size_t index = 0; index < length; ++index) {
        auto value = static_cast<unsigned char>(text[index]);
        block[field.offset + index] =
            std::byte{value < 0x80 ? value : static_cast<unsigned char>('_')};
    }
}

void putOctal(HeaderBlock& block, Field field, std::uint64_t value) {
    auto digits = field.length - 1;
    for (std::size_t index = digits; index-- > 0;) {
        block[field.offset + index] = static_cast<std::byte>('0' + (value & 7));
        value >>= 3;
    }
    block[field.offset + digits] = std::byte{0};
}

void putChecksum(HeaderBlock& block) {
    std::ranges::fill(
        std::span(block).subspan(checksumField.offset, checksumField.length),
        std::byte{' '}
    );

    std::uint64_t sum = 0;
    for (auto value : block) {
        sum += std::to_integer<std::uint8_t>(value);
    }

    Field digits{checksumField.offset, 7};
    putOctal(block, digits, sum);
}

void appendBlock(std::vector<std::byte>& out, const HeaderBlock& block) {
    out.insert(out.end(), block.begin(), block.end());
}

std::size_t decimalDigits(std::uint64_t value) {
    std::size_t digits = 1;
    while (value >= 10) {
        value /= 10;
        ++digits;
    }
    return digits;
}

void appendDecimal(std::string& out, std::uint64_t value) {
    std::array<char, 20> digits{};
    auto [end, error] = std::to_chars(digits.data(), digits.data() + digits.size(), value);
    static_cast<void>(error);
    out.append(digits.data(), end);
}

void appendRecord(std::string& out, std::string_view key, std::string_view value) {
    auto body = key.size() + value.size() + 3;
    auto length = body + decimalDigits(body);
    length = body + decimalDigits(length);

    appendDecimal(out, length);
    out.push_back(' ');
    out.append(key);
    out.push_back('=');
    out.append(value);
    out.push_back('\n');
}

void appendNumberRecord(std::string& out, std::string_view key, std::uint64_t value) {
    std::array<char, 20> digits{};
    auto [end, error] = std::to_chars(digits.data(), digits.data() + digits.size(), value);
    static_cast<void>(error);
    appendRecord(out, key, std::string_view(digits.data(), end));
}

void appendTimeRecord(std::string& out, std::int64_t seconds, std::uint32_t nanoseconds) {
    std::array<char, 32> text{};
    char* cursor = text.data();
    char* last = text.data() + text.size();
    if (seconds < 0 && nanoseconds != 0) {
        *cursor++ = '-';
        auto whole = static_cast<std::uint64_t>(-(seconds + 1));
        cursor = std::to_chars(cursor, last, whole).ptr;
        nanoseconds = 1'000'000'000U - nanoseconds;
    } else {
        cursor = std::to_chars(cursor, last, seconds).ptr;
    }

    if (nanoseconds != 0) {
        *cursor++ = '.';
        std::uint32_t scale = 100'000'000;
        while (nanoseconds != 0) {
            *cursor++ = static_cast<char>('0' + nanoseconds / scale);
            nanoseconds %= scale;
            scale /= 10;
        }
    }
    appendRecord(out, "mtime", std::string_view(text.data(), cursor));
}

std::optional<std::size_t> ustarSplit(std::string_view path) {
    for (std::size_t slash = path.find('/'); slash != std::string_view::npos;
         slash = path.find('/', slash + 1)) {
        if (slash > prefixField.length) {
            return std::nullopt;
        }
        auto name = path.size() - slash - 1;
        if (slash != 0 && name != 0 && name <= nameField.length) {
            return slash;
        }
    }
    return std::nullopt;
}

char typeflagFor(EntryKind kind) {
    switch (kind) {
    case EntryKind::Regular:
        return '0';
    case EntryKind::HardLink:
        return '1';
    case EntryKind::Symlink:
        return '2';
    case EntryKind::Directory:
        return '5';
    case EntryKind::CharDevice:
    case EntryKind::BlockDevice:
    case EntryKind::Fifo:
    case EntryKind::Other:
        break;
    }
    return 0;
}

HeaderBlock blankHeader(char typeflag, std::uint32_t mode) {
    HeaderBlock block{};
    putOctal(block, modeField, mode);
    putOctal(block, uidField, 0);
    putOctal(block, gidField, 0);
    putOctal(block, sizeField, 0);
    putOctal(block, mtimeField, 0);
    block[typeflagOffset] = static_cast<std::byte>(typeflag);
    putText(block, magicField, ustarMagic);
    return block;
}

Result<void> checkEntry(const WriteEntry& entry) {
    if (entry.path.empty() || entry.path.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "tar entry path empty or containing NUL");
    }
    if (entry.linkTarget.find('\0') != std::string_view::npos ||
        entry.uname.find('\0') != std::string_view::npos ||
        entry.gname.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::Malformed, "tar entry text contains NUL");
    }
    if (typeflagFor(entry.kind) == 0) {
        return fail(ErrorKind::Unsupported, "tar writer only writes files, directories and links");
    }

    bool linked = entry.kind == EntryKind::Symlink || entry.kind == EntryKind::HardLink;
    if (linked == entry.linkTarget.empty()) {
        return fail(ErrorKind::Malformed, "tar link target present exactly for links");
    }
    if (entry.kind != EntryKind::Regular && entry.size != 0) {
        return fail(ErrorKind::Malformed, "only regular tar entries carry data");
    }
    return {};
}

}

Result<void> encodeHeaders(const WriteEntry& entry, HeaderBuffers& buffers) {
    auto valid = checkEntry(entry);
    if (!valid) {
        return valid;
    }

    std::string_view path = entry.path;
    if (entry.kind == EntryKind::Directory && !path.ends_with('/')) {
        buffers.path.assign(path);
        buffers.path.push_back('/');
        path = buffers.path;
    }

    std::string& records = buffers.records;
    records.clear();
    HeaderBlock header = blankHeader(typeflagFor(entry.kind), entry.mode & permissionBits);
    if (fitsText(path, nameField)) {
        putText(header, nameField, path);
    } else if (auto split = isAscii(path) ? ustarSplit(path) : std::nullopt) {
        putText(header, prefixField, path.substr(0, *split));
        putText(header, nameField, path.substr(*split + 1));
    } else {
        appendRecord(records, "path", path);
        putText(header, nameField, path);
    }

    if (fitsText(entry.linkTarget, linkNameField)) {
        putText(header, linkNameField, entry.linkTarget);
    } else {
        appendRecord(records, "linkpath", entry.linkTarget);
        putText(header, linkNameField, entry.linkTarget);
    }

    if (entry.size <= maxOctal12) {
        putOctal(header, sizeField, entry.size);
    } else {
        appendNumberRecord(records, "size", entry.size);
    }

    if (entry.uid <= maxOctal8) {
        putOctal(header, uidField, entry.uid);
    } else {
        appendNumberRecord(records, "uid", entry.uid);
    }

    if (entry.gid <= maxOctal8) {
        putOctal(header, gidField, entry.gid);
    } else {
        appendNumberRecord(records, "gid", entry.gid);
    }

    bool secondsFit =
        entry.mtimeSeconds >= 0 && static_cast<std::uint64_t>(entry.mtimeSeconds) <= maxOctal12;
    if (secondsFit) {
        putOctal(header, mtimeField, static_cast<std::uint64_t>(entry.mtimeSeconds));
    }
    if (!secondsFit || entry.mtimeNanoseconds != 0) {
        appendTimeRecord(records, entry.mtimeSeconds, entry.mtimeNanoseconds);
    }

    if (fitsText(entry.uname, Field{unameField.offset, unameField.length - 1})) {
        putText(header, unameField, entry.uname);
    } else {
        appendRecord(records, "uname", entry.uname);
    }

    if (fitsText(entry.gname, Field{gnameField.offset, gnameField.length - 1})) {
        putText(header, gnameField, entry.gname);
    } else {
        appendRecord(records, "gname", entry.gname);
    }
    putChecksum(header);

    std::vector<std::byte>& out = buffers.blocks;
    out.clear();
    if (!records.empty()) {
        HeaderBlock pax = blankHeader('x', paxHeaderMode);
        putText(pax, nameField, paxHeaderName);
        putOctal(pax, sizeField, records.size());
        putChecksum(pax);
        appendBlock(out, pax);

        auto bytes = std::as_bytes(std::span(records));
        out.insert(out.end(), bytes.begin(), bytes.end());
        out.resize(out.size() + (blockSize - records.size() % blockSize) % blockSize);
    }
    appendBlock(out, header);
    return {};
}

Result<void> Writer::poison(const Error& error) {
    failure_ = error;
    return std::unexpected(error);
}

Result<void> Writer::check() const {
    if (failure_) {
        return std::unexpected(*failure_);
    }
    if (finished_) {
        return fail(ErrorKind::Malformed, "tar archive already finished");
    }
    return {};
}

Result<void> Writer::emit(std::span<const std::byte> data) {
    auto written = output_.write(data);
    if (!written) {
        return poison(written.error());
    }
    position_ += data.size();
    return {};
}

Result<void> Writer::closeEntry() {
    if (dataLeft_ != 0) {
        return poison(
            Error{.kind = ErrorKind::Malformed, .what = "tar entry data shorter than its size"}
        );
    }

    auto padding = (blockSize - position_ % blockSize) % blockSize;
    return emit(std::span(zeroBlock).first(padding));
}

Result<void> Writer::emitNow(const WriteEntry& entry) {
    auto encoded = encodeHeaders(entry, buffers_);
    if (!encoded) {
        return encoded;
    }

    auto written = emit(buffers_.blocks);
    if (!written) {
        return written;
    }
    dataLeft_ = entry.size;
    ++entries_;
    lastPath_.assign(entry.path);
    lastRegular_ = entry.kind == EntryKind::Regular;
    return {};
}

Result<void> Writer::emitLink(const WriteEntry& entry) {
    auto encoded = encodeHeaders(entry, buffers_);
    if (!encoded) {
        return encoded;
    }

    auto written = emit(buffers_.blocks);
    if (!written) {
        return written;
    }
    // NOTE: hardlinks carry no data, so emitting one always leaves no open data entry.
    dataLeft_ = 0;
    ++entries_;
    available_.insert(std::string(entry.path));
    lastPath_.assign(entry.path);
    lastRegular_ = false;
    return {};
}

Result<void> Writer::commitLast() {
    if (lastRegular_) {
        lastRegular_ = false;
        available_.insert(lastPath_);
    }
    return {};
}

bool Writer::targetAvailable(std::string_view target) const {
    return available_.find(target) != available_.end();
}

Result<void> Writer::flushReady() {
    bool progress = true;
    while (progress && !pending_.empty()) {
        progress = false;
        for (auto it = pending_.begin(); it != pending_.end();) {
            if (!targetAvailable(it->linkTarget)) {
                ++it;
                continue;
            }
            WriteEntry entry{
                .path = it->path,
                .linkTarget = it->linkTarget,
                .uname = it->uname,
                .gname = it->gname,
                .uid = it->uid,
                .gid = it->gid,
                .mtimeSeconds = it->mtimeSeconds,
                .mtimeNanoseconds = it->mtimeNanoseconds,
                .mode = it->mode,
                .kind = EntryKind::HardLink,
            };
            auto emitted = emitLink(entry);
            if (!emitted) {
                return emitted;
            }
            it = pending_.erase(it);
            progress = true;
        }
    }
    return {};
}

Result<void> Writer::add(const WriteEntry& entry) {
    auto usable = check();
    if (!usable) {
        return usable;
    }

    auto closed = closeEntry();
    if (!closed) {
        return closed;
    }
    auto committed = commitLast();
    if (!committed) {
        return committed;
    }
    auto flushed = flushReady();
    if (!flushed) {
        return flushed;
    }

    if (entry.kind == EntryKind::HardLink) {
        if (targetAvailable(entry.linkTarget)) {
            return emitLink(entry);
        }
        auto encoded = encodeHeaders(entry, buffers_);
        if (!encoded) {
            return encoded;
        }
        // NOTE: hold links whose target has not been written yet; finish emits
        // NOTE: them in dependency order so extraction never sees a dangling link.
        pending_.push_back(
            StoredLink{
                .path = std::string(entry.path),
                .linkTarget = std::string(entry.linkTarget),
                .uname = std::string(entry.uname),
                .gname = std::string(entry.gname),
                .uid = entry.uid,
                .gid = entry.gid,
                .mtimeSeconds = entry.mtimeSeconds,
                .mtimeNanoseconds = entry.mtimeNanoseconds,
                .mode = entry.mode,
            }
        );
        return {};
    }

    return emitNow(entry);
}

Result<void> Writer::write(std::span<const std::byte> data) {
    auto usable = check();
    if (!usable) {
        return usable;
    }
    if (data.size() > dataLeft_) {
        return poison(
            Error{.kind = ErrorKind::Malformed, .what = "tar entry data longer than its size"}
        );
    }

    dataLeft_ -= data.size();
    return emit(data);
}

Result<std::uint64_t> Writer::finish(bool durable) {
    auto usable = check();
    if (!usable) {
        return std::unexpected(usable.error());
    }

    auto closed = closeEntry();
    if (!closed) {
        return std::unexpected(closed.error());
    }

    auto committed = commitLast();
    if (!committed) {
        return std::unexpected(committed.error());
    }
    auto flushed = flushReady();
    if (!flushed) {
        return std::unexpected(flushed.error());
    }
    if (!pending_.empty()) {
        return std::unexpected(poison(
                                   Error{
                                       .kind = ErrorKind::Malformed,
                                       .what = "hard link target is not a regular entry"
                                   }
        )
                                   .error());
    }

    for (int count = 0; count < 2; ++count) {
        auto written = emit(zeroBlock);
        if (!written) {
            return std::unexpected(written.error());
        }
    }
    while (position_ % recordSize != 0) {
        auto written = emit(zeroBlock);
        if (!written) {
            return std::unexpected(written.error());
        }
    }

    finished_ = true;
    return output_.finish(durable);
}

}
