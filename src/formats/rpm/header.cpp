#include "formats/rpm/header.hpp"

#include "base/checked.hpp"

#include <array>
#include <limits>

namespace bale::rpm {

namespace {

[[nodiscard]] std::uint32_t loadBe32(std::span<const std::byte> bytes) {
    std::uint32_t value = 0;
    for (std::byte byte : bytes) {
        value = (value << 8) | static_cast<std::uint8_t>(byte);
    }
    return value;
}

struct Index {
    std::uint32_t tag = 0;
    TagType type = TagType::Null;
    std::uint64_t offset = 0;
    std::uint64_t count = 0;
};

struct Store {
    std::vector<std::byte> bytes;
    std::vector<Index> entries;
    std::uint64_t base = 0;
};

[[nodiscard]] Result<std::uint64_t> elementSize(TagType type, std::uint64_t at) {
    switch (type) {
    case TagType::Null:
        return 0;
    case TagType::Char:
    case TagType::Int8:
    case TagType::Bin:
        return 1;
    case TagType::Int16:
        return 2;
    case TagType::Int32:
        return 4;
    case TagType::Int64:
        return 8;
    case TagType::String:
    case TagType::StringArray:
    case TagType::I18nString:
        return tl::unexpected<Error>(
            fail(ErrorKind::Malformed, "string tag has no fixed size", at)
        );
    }
    return tl::unexpected<Error>(fail(ErrorKind::Malformed, "unknown rpm tag type", at));
}

[[nodiscard]] Result<void>
validateStrings(const Store& store, const Index& entry, const Limits& limits) {
    std::uint64_t strings = 0;
    std::uint64_t at = entry.offset;
    std::uint64_t end = store.bytes.size();
    while (strings < entry.count) {
        if (at >= end) {
            return fail(ErrorKind::Malformed, "rpm string tag runs past the store", store.base);
        }
        auto relative = checkedCast<std::size_t>(at);
        if (!relative) {
            return fail(ErrorKind::LimitExceeded, "rpm header store exceeds limit", store.base);
        }
        auto term = std::find(
            store.bytes.begin() + static_cast<std::ptrdiff_t>(*relative),
            store.bytes.end(),
            std::byte{0}
        );
        if (term == store.bytes.end()) {
            return fail(ErrorKind::Malformed, "rpm string tag is not terminated", store.base);
        }
        auto length = static_cast<std::uint64_t>(term - store.bytes.begin()) - at;
        if (length > limits.maxStringBytes) {
            return fail(ErrorKind::LimitExceeded, "rpm string tag exceeds limit", store.base);
        }
        at += length + 1;
        ++strings;
    }
    return {};
}

[[nodiscard]] Result<Index> parseIndex(std::span<const std::byte> record) {
    Index entry;
    entry.tag = loadBe32(record.first(4));
    auto rawType = loadBe32(record.subspan(4, 4));
    if (rawType > static_cast<std::uint32_t>(TagType::I18nString)) {
        return fail(ErrorKind::Malformed, "unknown rpm tag type");
    }
    entry.type = static_cast<TagType>(rawType);
    entry.offset = loadBe32(record.subspan(8, 4));
    entry.count = loadBe32(record.subspan(12, 4));
    return entry;
}

[[nodiscard]] Result<bool>
hasHeaderMagic(const File& file, std::uint64_t at, std::uint64_t fileSize) {
    if (!fitsWithin(at, std::uint64_t{4}, fileSize)) {
        return false;
    }
    std::array<std::byte, 4> probe{};
    auto read = file.readExactAt(at, probe);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    return probe[0] == headerMagic[0] && probe[1] == headerMagic[1] && probe[2] == headerMagic[2] &&
        probe[3] == std::byte{headerVersion};
}

[[nodiscard]] Result<std::uint64_t>
skipHeaderPadding(const File& file, std::uint64_t at, std::uint64_t limit) {
    // NOTE: rpmbuild emits the payload immediately after the main header,
    // but a writer that pads the main header to 8 bytes leaves zero bytes
    // no compressor stream starts with, so tolerate them up to the padding.
    while (at < limit) {
        std::array<std::byte, 1> probe{};
        auto read = file.readAt(at, probe);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        if (*read == 0) {
            return at;
        }
        if (probe[0] != std::byte{0}) {
            return at;
        }
        ++at;
    }
    return at;
}

[[nodiscard]] Result<Store> parseStore(
    const File& file,
    std::uint64_t at,
    std::uint64_t fileSize,
    const Limits& limits,
    std::uint64_t& nextOffset,
    std::uint64_t& nextPadded
) {
    auto end = checkedAdd(at, headerPrefixSize);
    if (!end || *end > fileSize) {
        return fail(ErrorKind::Truncated, "rpm archive ends inside a header record", at);
    }

    std::array<std::byte, headerPrefixSize> prefix{};
    auto read = file.readExactAt(at, prefix);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    if (!std::equal(prefix.begin(), prefix.begin() + 3, headerMagic.begin())) {
        return fail(ErrorKind::Malformed, "unknown rpm header magic", at);
    }
    if (prefix[3] != std::byte{headerVersion}) {
        return fail(ErrorKind::Unsupported, "unsupported rpm header version", at);
    }

    std::span<const std::byte> body(prefix);
    auto count = loadBe32(body.subspan(8, 4));
    auto storeBytes = loadBe32(body.subspan(12, 4));
    if (count > limits.maxHeaderEntries) {
        return fail(ErrorKind::LimitExceeded, "rpm header entry count exceeds limit", at);
    }
    if (storeBytes > limits.maxHeaderBytes) {
        return fail(ErrorKind::LimitExceeded, "rpm header store exceeds limit", at);
    }

    auto indexBytes = checkedMul(count, headerIndexSize);
    if (!indexBytes) {
        return fail(ErrorKind::Malformed, "rpm header index size overflows", at);
    }
    auto storeStart = checkedAdd(*end, *indexBytes);
    if (!storeStart) {
        return fail(ErrorKind::Malformed, "rpm header index size overflows", at);
    }
    auto storeEnd = checkedAdd(*storeStart, static_cast<std::uint64_t>(storeBytes));
    if (!storeEnd || *storeEnd > fileSize) {
        return fail(ErrorKind::Truncated, "rpm archive ends inside a header store", at);
    }

    Store store;
    store.base = at;
    if (count > 0) {
        auto rawBytes = checkedCast<std::size_t>(*indexBytes);
        if (!rawBytes) {
            return fail(ErrorKind::LimitExceeded, "rpm header index exceeds limit", at);
        }
        std::vector<std::byte> raw(*rawBytes);
        auto indexRead = file.readExactAt(*end, raw);
        if (!indexRead) {
            return tl::unexpected<Error>(indexRead.error());
        }
        store.entries.reserve(count);
        for (std::uint64_t index = 0; index < count; ++index) {
            auto offset = index * headerIndexSize;
            auto parsed =
                parseIndex(std::span<const std::byte>(raw).subspan(offset, headerIndexSize));
            if (!parsed) {
                parsed.error().offset = at;
                return tl::unexpected<Error>(parsed.error());
            }
            store.entries.push_back(*parsed);
        }
    }

    store.bytes.resize(storeBytes);
    if (storeBytes > 0) {
        auto dataRead = file.readExactAt(*storeStart, store.bytes);
        if (!dataRead) {
            return tl::unexpected<Error>(dataRead.error());
        }
    }

    for (const auto& entry : store.entries) {
        if (entry.type == TagType::String || entry.type == TagType::StringArray ||
            entry.type == TagType::I18nString) {
            if (entry.count == 0) {
                return fail(ErrorKind::Malformed, "rpm string tag is empty", at);
            }
            if (entry.offset > store.bytes.size()) {
                return fail(ErrorKind::Malformed, "rpm tag offset out of range", at);
            }
            auto checked = validateStrings(store, entry, limits);
            if (!checked) {
                return tl::unexpected<Error>(checked.error());
            }
            continue;
        }
        auto unit = elementSize(entry.type, at);
        if (!unit) {
            return tl::unexpected<Error>(unit.error());
        }
        auto total = checkedMul(*unit, entry.count);
        if (!total) {
            return fail(ErrorKind::Malformed, "rpm tag size overflows", at);
        }
        auto last = checkedAdd(entry.offset, *total);
        if (!last || *last > store.bytes.size()) {
            return fail(ErrorKind::Malformed, "rpm tag range out of bounds", at);
        }
    }

    auto padded = (*storeEnd + 7) & ~std::uint64_t{7};
    if (padded < *storeEnd) {
        return fail(ErrorKind::Malformed, "rpm header end overflows", at);
    }
    nextOffset = *storeEnd;
    nextPadded = padded;
    return store;
}

[[nodiscard]] const Index* findTag(const Store& store, std::uint32_t tag) {
    for (const auto& entry : store.entries) {
        if (entry.tag == tag) {
            return &entry;
        }
    }
    return nullptr;
}

[[nodiscard]] Result<std::string> readString(const Store& store, std::uint32_t tag, bool required) {
    const auto* entry = findTag(store, tag);
    if (entry == nullptr) {
        if (required) {
            return fail(ErrorKind::Malformed, "rpm header lacks a required tag", store.base);
        }
        return std::string{};
    }
    if (entry->type != TagType::String || entry->count != 1) {
        return fail(ErrorKind::Malformed, "rpm tag has the wrong type", store.base);
    }
    auto at = checkedCast<std::size_t>(entry->offset);
    if (!at || *at >= store.bytes.size()) {
        return fail(ErrorKind::Malformed, "rpm tag offset out of range", store.base);
    }
    const char* text = reinterpret_cast<const char*>(store.bytes.data() + *at);
    std::size_t length = 0;
    while (*at + length < store.bytes.size() && text[length] != '\0') {
        ++length;
    }
    if (*at + length >= store.bytes.size()) {
        return fail(ErrorKind::Malformed, "rpm string tag is not terminated", store.base);
    }
    return std::string(text, length);
}

[[nodiscard]] Result<Compression> mapCompressor(std::string_view name, std::uint64_t at) {
    if (name == "gzip") {
        return Compression::Gzip;
    }
    if (name == "bzip2") {
        return Compression::Bzip2;
    }
    if (name == "xz") {
        return Compression::Xz;
    }
    if (name == "zstd") {
        return Compression::Zstd;
    }
    if (name == "none" || name.empty()) {
        return Compression::None;
    }
    return fail(ErrorKind::Unsupported, "unsupported rpm payload compressor", at);
}

}

bool looksLikeRpm(std::span<const std::byte> head) {
    if (head.size() < leadMagic.size()) {
        return false;
    }
    return std::equal(leadMagic.begin(), leadMagic.end(), head.begin());
}

Result<Package> parsePackage(const File& file, std::uint64_t fileSize, const Limits& limits) {
    if (fileSize < leadSize) {
        std::array<std::byte, leadMagic.size()> magic{};
        auto have = static_cast<std::size_t>(std::min<std::uint64_t>(fileSize, magic.size()));
        if (have > 0) {
            auto read = file.readExactAt(0, std::span(magic).first(have));
            if (!read) {
                return tl::unexpected<Error>(read.error());
            }
        }
        if (!looksLikeRpm(std::span<const std::byte>(magic).first(have))) {
            return fail(ErrorKind::Malformed, "not an rpm package");
        }
        return fail(ErrorKind::Truncated, "rpm archive ends inside the lead", fileSize);
    }

    std::array<std::byte, leadSize> lead{};
    auto leadRead = file.readExactAt(0, lead);
    if (!leadRead) {
        return tl::unexpected<Error>(leadRead.error());
    }
    if (!looksLikeRpm(lead)) {
        return fail(ErrorKind::Malformed, "not an rpm package");
    }
    std::uint8_t major = static_cast<std::uint8_t>(lead[4]);
    if (major < majorV3) {
        return fail(ErrorKind::Unsupported, "rpm v1/v2 layouts are not supported", 4);
    }
    if (major != majorV3 && major != majorV4) {
        return fail(ErrorKind::Malformed, "unknown rpm version", 4);
    }

    Package package;
    std::uint64_t afterSignature = 0;
    std::uint64_t signaturePadded = 0;
    {
        auto signature =
            parseStore(file, leadSize, fileSize, limits, afterSignature, signaturePadded);
        if (!signature) {
            return tl::unexpected<Error>(signature.error());
        }
        if (signature->entries.size() > limits.maxSignatureTags) {
            return fail(ErrorKind::LimitExceeded, "rpm signature count exceeds limit", leadSize);
        }
        package.signatureTags.reserve(signature->entries.size());
        for (const auto& entry : signature->entries) {
            package.signatureTags.push_back(entry.tag);
        }
    }

    // NOTE: rpmbuild pads the signature header to 8 bytes but some writers
    // start the main header immediately; accept either, magic-checked.
    std::uint64_t mainAt = signaturePadded;
    {
        auto magic = hasHeaderMagic(file, afterSignature, fileSize);
        if (!magic) {
            return tl::unexpected<Error>(magic.error());
        }
        if (*magic) {
            mainAt = afterSignature;
        }
    }

    std::uint64_t headerEnd = 0;
    std::uint64_t headerPadded = 0;
    {
        auto header = parseStore(file, mainAt, fileSize, limits, headerEnd, headerPadded);
        if (!header) {
            return tl::unexpected<Error>(header.error());
        }
        auto name = readString(*header, tagName, true);
        if (!name) {
            return tl::unexpected<Error>(name.error());
        }
        auto version = readString(*header, tagVersion, true);
        if (!version) {
            return tl::unexpected<Error>(version.error());
        }
        auto release = readString(*header, tagRelease, true);
        if (!release) {
            return tl::unexpected<Error>(release.error());
        }
        auto arch = readString(*header, tagArch, false);
        if (!arch) {
            return tl::unexpected<Error>(arch.error());
        }
        auto os = readString(*header, tagOs, false);
        if (!os) {
            return tl::unexpected<Error>(os.error());
        }
        auto format = readString(*header, tagPayloadFormat, false);
        if (!format) {
            return tl::unexpected<Error>(format.error());
        }
        auto compressor = readString(*header, tagPayloadCompressor, false);
        if (!compressor) {
            return tl::unexpected<Error>(compressor.error());
        }
        auto flags = readString(*header, tagPayloadFlags, false);
        if (!flags) {
            return tl::unexpected<Error>(flags.error());
        }
        package.name = std::move(*name);
        package.version = std::move(*version);
        package.release = std::move(*release);
        package.arch = std::move(*arch);
        package.os = std::move(*os);
        package.payloadFormat = format->empty() ? std::string("cpio") : std::move(*format);
        package.payloadCompressor =
            compressor->empty() ? std::string("gzip") : std::move(*compressor);
        package.payloadFlags = std::move(*flags);
    }

    if (package.payloadFormat != "cpio") {
        return fail(ErrorKind::Unsupported, "unsupported rpm payload format", afterSignature);
    }
    auto compression = mapCompressor(package.payloadCompressor, afterSignature);
    if (!compression) {
        return tl::unexpected<Error>(compression.error());
    }
    package.compression = *compression;
    package.uncompressed = *compression == Compression::None;
    auto payloadStart = skipHeaderPadding(file, headerEnd, std::min(headerPadded, fileSize));
    if (!payloadStart) {
        return tl::unexpected<Error>(payloadStart.error());
    }
    package.payloadOffset = *payloadStart;
    if (package.payloadOffset > fileSize) {
        return fail(
            ErrorKind::Truncated,
            "rpm archive ends before the payload",
            package.payloadOffset
        );
    }
    package.payloadBytes = fileSize - package.payloadOffset;
    if (package.payloadBytes == 0) {
        return fail(ErrorKind::Truncated, "rpm archive has no payload", package.payloadOffset);
    }
    return package;
}

}
