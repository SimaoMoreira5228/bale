#include "formats/zip/writer.hpp"

#include "base/checked.hpp"
#include "base/endian.hpp"
#include "formats/zip/reader.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>

namespace bale::zip {

namespace {

constexpr std::uint32_t localHeaderSignature = 0x04034b50;
constexpr std::uint32_t centralHeaderSignature = 0x02014b50;
constexpr std::uint32_t endRecordSignature = 0x06054b50;
constexpr std::uint32_t zip64EndRecordSignature = 0x06064b50;
constexpr std::uint32_t zip64LocatorSignature = 0x07064b50;
constexpr std::size_t localHeaderSize = 30;
constexpr std::uint16_t zip64ExtraId = 0x0001;
constexpr std::uint16_t extendedTimestampId = 0x5455;
constexpr std::uint16_t versionMadeBy = (3 << 8) | 45;
constexpr std::uint16_t versionStored = 10;
constexpr std::uint16_t versionDeflate = 20;
constexpr std::uint16_t versionZip64 = 45;
constexpr std::uint32_t saturated32 = 0xFFFFFFFF;
constexpr std::uint16_t saturated16 = 0xFFFF;
constexpr std::uint16_t dosEpochDate = (1 << 5) | 1;
constexpr std::uint32_t msdosDirectory = 0x10;
constexpr std::uint32_t typeRegular = 0100000;
constexpr std::uint32_t typeDirectory = 0040000;
constexpr std::uint32_t typeSymlink = 0120000;
constexpr std::uint32_t permissionBits = 07777;
constexpr std::size_t outputBufferSize = std::size_t{256} * 1024;
constexpr std::size_t minBufferBytes = 64;

template <std::unsigned_integral T> void appendLe(std::vector<std::byte>& out, T value) {
    std::array<std::byte, sizeof(T)> bytes{};
    storeLe(bytes.data(), value);
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void appendText(std::vector<std::byte>& out, std::string_view text) {
    auto bytes = std::as_bytes(std::span(text.data(), text.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

std::uint32_t clamp32(std::uint64_t value) {
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(value, saturated32));
}

bool isAscii(std::string_view text) {
    return std::ranges::all_of(text, [](char value) {
        return static_cast<unsigned char>(value) < 0x80;
    });
}

std::uint16_t versionFor(std::uint16_t method, std::string_view name, bool zip64) {
    if (zip64) {
        return versionZip64;
    }
    if (method == methodDeflate || name.ends_with('/')) {
        return versionDeflate;
    }
    return versionStored;
}

void setDosTime(std::optional<std::int64_t> seconds, CentralRecord& record) {
    record.dosDate = dosEpochDate;
    record.dosTime = 0;
    if (!seconds) {
        return;
    }

    std::chrono::sys_seconds point{std::chrono::seconds{*seconds}};
    auto midnight = std::chrono::floor<std::chrono::days>(point);
    std::chrono::year_month_day date{midnight};
    int year = static_cast<int>(date.year());
    if (year < 1980) {
        return;
    }
    if (year > 2107) {
        record.dosDate = static_cast<std::uint16_t>((127 << 9) | (12 << 5) | 31);
        record.dosTime = static_cast<std::uint16_t>((23 << 11) | (59 << 5) | 29);
        return;
    }

    std::chrono::hh_mm_ss time{point - midnight};
    auto years = static_cast<unsigned>(year - 1980);
    auto month = static_cast<unsigned>(date.month());
    auto day = static_cast<unsigned>(date.day());
    auto hours = static_cast<unsigned>(time.hours().count());
    auto minutes = static_cast<unsigned>(time.minutes().count());
    auto halfSeconds = static_cast<unsigned>(time.seconds().count() / 2);
    record.dosDate = static_cast<std::uint16_t>((years << 9) | (month << 5) | day);
    record.dosTime = static_cast<std::uint16_t>((hours << 11) | (minutes << 5) | halfSeconds);
}

std::uint32_t externalAttributes(const WriteEntry& entry) {
    switch (entry.kind) {
    case WriteKind::Directory:
        return ((typeDirectory | (entry.mode.value_or(0755) & permissionBits)) << 16) |
            msdosDirectory;
    case WriteKind::Symlink:
        return (typeSymlink | 0777) << 16;
    case WriteKind::File:
        break;
    }
    return (typeRegular | (entry.mode.value_or(0644) & permissionBits)) << 16;
}

bool mayNeedZip64(std::uint64_t size) {
    return size >= saturated32 - size / 256 - 1024;
}

}

void appendCentralHeader(const CentralRecord& record, std::vector<std::byte>& out) {
    bool bigUncompressed = record.uncompressedSize >= saturated32;
    bool bigCompressed = record.compressedSize >= saturated32;
    bool bigOffset = record.localHeaderOffset >= saturated32;
    bool zip64 = bigUncompressed || bigCompressed || bigOffset;

    std::uint16_t zip64Size = static_cast<std::uint16_t>(
        8 *
        (static_cast<int>(bigUncompressed) + static_cast<int>(bigCompressed) +
         static_cast<int>(bigOffset))
    );
    std::uint16_t extraSize = zip64 ? static_cast<std::uint16_t>(4 + zip64Size) : 0;
    if (record.mtimeSeconds) {
        extraSize = static_cast<std::uint16_t>(extraSize + 9);
    }

    appendLe(out, centralHeaderSignature);
    appendLe(out, versionMadeBy);
    appendLe(out, versionFor(record.method, record.name, zip64));
    appendLe(out, record.flags);
    appendLe(out, record.method);
    appendLe(out, record.dosTime);
    appendLe(out, record.dosDate);
    appendLe(out, record.crc32);
    appendLe(out, clamp32(record.compressedSize));
    appendLe(out, clamp32(record.uncompressedSize));
    appendLe(out, static_cast<std::uint16_t>(record.name.size()));
    appendLe(out, extraSize);
    appendLe(out, std::uint16_t{0});
    appendLe(out, std::uint16_t{0});
    appendLe(out, std::uint16_t{0});
    appendLe(out, record.externalAttributes);
    appendLe(out, clamp32(record.localHeaderOffset));
    appendText(out, record.name);

    if (zip64) {
        appendLe(out, zip64ExtraId);
        appendLe(out, zip64Size);
        if (bigUncompressed) {
            appendLe(out, record.uncompressedSize);
        }
        if (bigCompressed) {
            appendLe(out, record.compressedSize);
        }
        if (bigOffset) {
            appendLe(out, record.localHeaderOffset);
        }
    }
    if (record.mtimeSeconds) {
        appendLe(out, extendedTimestampId);
        appendLe(out, std::uint16_t{5});
        out.push_back(std::byte{1});
        appendLe(out, static_cast<std::uint32_t>(*record.mtimeSeconds));
    }
}

void appendEndRecords(
    std::uint64_t entryCount,
    std::uint64_t directoryOffset,
    std::uint64_t directorySize,
    std::vector<std::byte>& out
) {
    bool zip64 =
        entryCount >= saturated16 || directoryOffset >= saturated32 || directorySize >= saturated32;
    if (zip64) {
        constexpr std::uint64_t zip64EndBody = 44;
        auto recordOffset = directoryOffset + directorySize;

        appendLe(out, zip64EndRecordSignature);
        appendLe(out, zip64EndBody);
        appendLe(out, versionMadeBy);
        appendLe(out, versionZip64);
        appendLe(out, std::uint32_t{0});
        appendLe(out, std::uint32_t{0});
        appendLe(out, entryCount);
        appendLe(out, entryCount);
        appendLe(out, directorySize);
        appendLe(out, directoryOffset);

        appendLe(out, zip64LocatorSignature);
        appendLe(out, std::uint32_t{0});
        appendLe(out, recordOffset);
        appendLe(out, std::uint32_t{1});
    }

    auto count = static_cast<std::uint16_t>(std::min<std::uint64_t>(entryCount, saturated16));
    appendLe(out, endRecordSignature);
    appendLe(out, std::uint16_t{0});
    appendLe(out, std::uint16_t{0});
    appendLe(out, count);
    appendLe(out, count);
    appendLe(out, clamp32(directorySize));
    appendLe(out, clamp32(directoryOffset));
    appendLe(out, std::uint16_t{0});
}

Writer::Writer(File file, const WriterOptions& options, std::optional<DeflateEncoder> encoder) :
    file_(std::move(file)), options_(options), encoder_(std::move(encoder)),
    input_(options.bufferBytes) {
    output_.reserve(outputBufferSize);
    if (encoder_) {
        compressed_.resize(DeflateEncoder::compressBound(options.bufferBytes));
    }
}

Result<Writer> Writer::create(File file, const WriterOptions& options) {
    if (options.level < 0 || options.level > 9) {
        return fail(ErrorKind::Unsupported, "deflate level must be between 0 and 9");
    }
    if (options.bufferBytes < minBufferBytes ||
        options.bufferBytes > std::numeric_limits<std::uint32_t>::max() / 2) {
        return fail(ErrorKind::LimitExceeded, "ZIP buffer size outside the supported range");
    }

    std::optional<DeflateEncoder> encoder;
    if (options.level > 0) {
        auto created = DeflateEncoder::create(options.level);
        if (!created) {
            return std::unexpected(created.error());
        }
        encoder.emplace(std::move(*created));
    }
    return Writer(std::move(file), options, std::move(encoder));
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
        return fail(ErrorKind::Malformed, "ZIP archive already finished");
    }
    return {};
}

Result<void> Writer::flush() {
    if (output_.empty()) {
        return {};
    }

    auto written = file_.append(output_);
    if (!written) {
        return poison(written.error());
    }
    flushed_ += output_.size();
    output_.clear();
    return {};
}

Result<void> Writer::put(std::span<const std::byte> data) {
    auto end = checkedAdd<std::uint64_t>(position_, data.size());
    if (!end) {
        return poison(
            Error{.kind = ErrorKind::LimitExceeded, .what = "ZIP archive size overflows"}
        );
    }

    if (output_.size() + data.size() > outputBufferSize) {
        auto flushed = flush();
        if (!flushed) {
            return flushed;
        }
    }
    if (data.size() >= outputBufferSize) {
        auto written = file_.append(data);
        if (!written) {
            return poison(written.error());
        }
        flushed_ += data.size();
    } else {
        output_.insert(output_.end(), data.begin(), data.end());
    }
    position_ = *end;
    return {};
}

Result<void> Writer::writeLocalHeader(bool reserveZip64) {
    localZip64_ = reserveZip64;
    std::uint16_t extraSize = reserveZip64 ? 20 : 0;
    if (record_.mtimeSeconds) {
        extraSize = static_cast<std::uint16_t>(extraSize + 9);
    }

    header_.clear();
    appendLe(header_, localHeaderSignature);
    appendLe(header_, versionFor(record_.method, record_.name, reserveZip64));
    appendLe(header_, record_.flags);
    appendLe(header_, record_.method);
    appendLe(header_, record_.dosTime);
    appendLe(header_, record_.dosDate);
    appendLe(header_, record_.crc32);
    appendLe(header_, reserveZip64 ? saturated32 : clamp32(record_.compressedSize));
    appendLe(header_, reserveZip64 ? saturated32 : clamp32(record_.uncompressedSize));
    appendLe(header_, static_cast<std::uint16_t>(record_.name.size()));
    appendLe(header_, extraSize);
    appendText(header_, record_.name);
    if (reserveZip64) {
        appendLe(header_, zip64ExtraId);
        appendLe(header_, std::uint16_t{16});
        appendLe(header_, record_.uncompressedSize);
        appendLe(header_, record_.compressedSize);
    }
    if (record_.mtimeSeconds) {
        appendLe(header_, extendedTimestampId);
        appendLe(header_, std::uint16_t{5});
        header_.push_back(std::byte{1});
        appendLe(header_, static_cast<std::uint32_t>(*record_.mtimeSeconds));
    }
    return put(header_);
}

Result<void> Writer::writeWhole(std::span<const std::byte> data, bool compressible) {
    record_.crc32 = Crc32::of(data);
    record_.uncompressedSize = data.size();
    record_.compressedSize = data.size();
    record_.method = methodStored;

    std::span<const std::byte> stored = data;
    if (encoder_ && compressible && !data.empty()) {
        auto size = encoder_->compress(data, compressed_);
        if (!size) {
            return poison(size.error());
        }
        if (*size < data.size()) {
            record_.method = methodDeflate;
            record_.compressedSize = *size;
            stored = std::span(compressed_).first(*size);
        }
    }

    auto header = writeLocalHeader(false);
    if (!header) {
        return header;
    }
    auto written = put(stored);
    if (!written) {
        return written;
    }
    appendCentralHeader(record_, central_);
    phase_ = Phase::Idle;
    return {};
}

Result<void> Writer::deflate(std::span<const std::byte> data, EncodeFlush flush) {
    if (!encoder_) {
        return poison(Error{.kind = ErrorKind::Malformed, .what = "ZIP writer has no encoder"});
    }

    DeflateEncoder& encoder = *encoder_;
    while (true) {
        auto step = encoder.stream(data, compressed_, flush);
        if (!step) {
            return poison(step.error());
        }

        data = data.subspan(step->consumed);
        record_.compressedSize += step->produced;
        auto written = put(std::span(compressed_).first(step->produced));
        if (!written) {
            return written;
        }
        if (step->finished) {
            return {};
        }
    }
}

Result<void> Writer::startStreaming() {
    auto probe = std::span<const std::byte>(input_);
    crc_ = Crc32{};
    crc_.update(probe);
    record_.method = methodStored;

    std::size_t probeSize = probe.size();
    if (encoder_) {
        auto reset = encoder_->reset();
        if (!reset) {
            return poison(reset.error());
        }
        auto step = encoder_->stream(probe, compressed_, EncodeFlush::Sync);
        if (!step) {
            return poison(step.error());
        }
        if (step->finished && step->produced < probe.size()) {
            record_.method = methodDeflate;
            probeSize = step->produced;
        }
    }

    auto header = writeLocalHeader(mayNeedZip64(record_.uncompressedSize));
    if (!header) {
        return header;
    }

    phase_ = Phase::Streaming;
    record_.compressedSize = probeSize;
    if (record_.method == methodDeflate) {
        return put(std::span(compressed_).first(probeSize));
    }
    return put(probe);
}

Result<void> Writer::patchLocalHeader() {
    if (!localZip64_ &&
        (record_.compressedSize >= saturated32 || record_.uncompressedSize >= saturated32)) {
        return poison(
            Error{.kind = ErrorKind::LimitExceeded, .what = "ZIP entry outgrew its local header"}
        );
    }

    auto flushed = flush();
    if (!flushed) {
        return flushed;
    }

    std::array<std::byte, 12> sizes{};
    storeLe(sizes.data(), record_.crc32);
    storeLe(sizes.data() + 4, localZip64_ ? saturated32 : clamp32(record_.compressedSize));
    storeLe(sizes.data() + 8, localZip64_ ? saturated32 : clamp32(record_.uncompressedSize));
    auto patched = file_.writeAt(record_.localHeaderOffset + 14, sizes);
    if (!patched) {
        return poison(patched.error());
    }

    if (localZip64_) {
        std::array<std::byte, 16> extra{};
        storeLe(extra.data(), record_.uncompressedSize);
        storeLe(extra.data() + 8, record_.compressedSize);
        auto at = record_.localHeaderOffset + localHeaderSize + record_.name.size() + 4;
        auto written = file_.writeAt(at, extra);
        if (!written) {
            return poison(written.error());
        }
    }
    return {};
}

Result<void> Writer::closeEntry() {
    if (phase_ == Phase::Idle) {
        return {};
    }
    if (dataLeft_ != 0) {
        return poison(
            Error{.kind = ErrorKind::Malformed, .what = "ZIP entry data shorter than its size"}
        );
    }
    if (phase_ == Phase::Buffering) {
        return writeWhole(std::span(input_).first(buffered_), true);
    }

    if (record_.method == methodDeflate) {
        auto ended = deflate({}, EncodeFlush::Finish);
        if (!ended) {
            return ended;
        }
    }
    record_.crc32 = crc_.value();
    auto patched = patchLocalHeader();
    if (!patched) {
        return patched;
    }

    appendCentralHeader(record_, central_);
    phase_ = Phase::Idle;
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

    if (entry.path.empty() || entry.path.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "ZIP entry path empty or containing NUL");
    }
    bool symlink = entry.kind == WriteKind::Symlink;
    if (symlink == entry.linkTarget.empty()) {
        return fail(ErrorKind::Malformed, "ZIP link target present exactly for symlinks");
    }
    if (entry.kind != WriteKind::File && entry.size != 0) {
        return fail(ErrorKind::Malformed, "only regular ZIP entries carry data");
    }

    name_.assign(entry.path);
    if (entry.kind == WriteKind::Directory && !name_.ends_with('/')) {
        name_.push_back('/');
    }
    if (name_.size() > saturated16) {
        return fail(ErrorKind::LimitExceeded, "ZIP entry name longer than 65535 bytes");
    }

    record_ = CentralRecord{};
    record_.name = name_;
    record_.localHeaderOffset = position_;
    record_.uncompressedSize = entry.size;
    record_.externalAttributes = externalAttributes(entry);
    record_.flags = isAscii(name_) ? 0 : flagUtf8;
    setDosTime(entry.mtimeSeconds, record_);
    if (entry.mtimeSeconds) {
        record_.mtimeSeconds = checkedCast<std::int32_t>(*entry.mtimeSeconds);
    }
    ++entries_;

    if (entry.kind == WriteKind::Directory) {
        phase_ = Phase::Buffering;
        return writeWhole({}, false);
    }
    if (symlink) {
        phase_ = Phase::Buffering;
        return writeWhole(std::as_bytes(std::span(entry.linkTarget)), false);
    }

    dataLeft_ = entry.size;
    buffered_ = 0;
    phase_ = Phase::Buffering;
    return {};
}

Result<void> Writer::write(std::span<const std::byte> data) {
    auto usable = check();
    if (!usable) {
        return usable;
    }
    if (phase_ == Phase::Idle || data.size() > dataLeft_) {
        return poison(
            Error{.kind = ErrorKind::Malformed, .what = "ZIP entry data longer than its size"}
        );
    }
    dataLeft_ -= data.size();

    if (phase_ == Phase::Buffering) {
        if (record_.uncompressedSize <= input_.size()) {
            std::ranges::copy(data, input_.begin() + static_cast<std::ptrdiff_t>(buffered_));
            buffered_ += data.size();
            return {};
        }

        auto room = std::min(data.size(), input_.size() - buffered_);
        std::ranges::copy(
            data.first(room),
            input_.begin() + static_cast<std::ptrdiff_t>(buffered_)
        );
        buffered_ += room;
        data = data.subspan(room);
        if (buffered_ < input_.size()) {
            return {};
        }

        auto started = startStreaming();
        if (!started) {
            return started;
        }
    }

    if (data.empty()) {
        return {};
    }
    crc_.update(data);
    if (record_.method == methodDeflate) {
        return deflate(data, EncodeFlush::None);
    }
    record_.compressedSize += data.size();
    return put(data);
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

    auto directoryOffset = position_;
    auto directorySize = central_.size();
    appendEndRecords(entries_, directoryOffset, directorySize, central_);
    auto written = put(central_);
    if (!written) {
        return std::unexpected(written.error());
    }
    auto flushed = flush();
    if (!flushed) {
        return std::unexpected(flushed.error());
    }
    if (durable) {
        auto synced = file_.sync();
        if (!synced) {
            return std::unexpected(poison(synced.error()).error());
        }
    }

    finished_ = true;
    return position_;
}

}
