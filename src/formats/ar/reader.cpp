#include "formats/ar/reader.hpp"

#include "base/checked.hpp"

#include <array>
#include <utility>

namespace bale::ar {

namespace {

bool isSymbolTable(std::string_view raw) {
    return raw == "/" || raw == "/SYM64/" || raw == "SYMDEF" || raw == "__.SYMDEF";
}

bool isStringTable(std::string_view raw) {
    return raw == "//";
}

bool isGnuReference(std::string_view raw) {
    if (raw.size() < 2 || raw.front() != '/') {
        return false;
    }

    for (char digit : raw.substr(1)) {
        if (digit < '0' || digit > '9') {
            return false;
        }
    }
    return true;
}

Result<std::uint64_t> parseTableOffset(std::string_view raw, std::uint64_t at) {
    std::uint64_t value = 0;
    for (char digit : raw.substr(1)) {
        auto scaled = checkedMul(value, 10u);
        if (!scaled) {
            return fail(ErrorKind::Malformed, "ar string table offset overflows", at);
        }

        auto next = checkedAdd(*scaled, static_cast<std::uint64_t>(digit - '0'));
        if (!next) {
            return fail(ErrorKind::Malformed, "ar string table offset overflows", at);
        }
        value = *next;
    }
    return value;
}

}

Result<Reader> Reader::open(File file, const Limits& limits) {
    auto size = file.size();
    if (!size) {
        return tl::unexpected<Error>(size.error());
    }

    std::array<std::byte, magic.size()> head{};
    if (*size < head.size()) {
        return fail(ErrorKind::Malformed, "not an ar archive");
    }

    auto read = file.readExactAt(0, head);
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }
    if (!looksLikeAr(head)) {
        return fail(ErrorKind::Malformed, "not an ar archive");
    }

    Reader reader(std::move(file), limits);
    auto indexed = reader.index(*size);
    if (!indexed) {
        return tl::unexpected<Error>(indexed.error());
    }
    return reader;
}

Result<void> Reader::index(std::uint64_t fileSize) {
    auto offset = magic.size();
    while (offset < fileSize) {
        if (entries_.size() >= limits_.maxEntries) {
            return fail(ErrorKind::LimitExceeded, "ar entry count exceeds limit", offset);
        }

        auto end = checkedAdd(offset, headerSize);
        if (!end || *end > fileSize) {
            return fail(ErrorKind::Truncated, "ar archive ends inside a member header", offset);
        }

        std::array<std::byte, headerSize> header{};
        auto read = file_.readExactAt(offset, header);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }

        auto member = parseMember(header, offset);
        if (!member) {
            return tl::unexpected<Error>(member.error());
        }

        auto added = addMember(*member, fileSize);
        if (!added) {
            return tl::unexpected<Error>(added.error());
        }

        auto dataEnd = checkedAdd(member->dataOffset, member->size);
        if (!dataEnd) {
            return fail(ErrorKind::Malformed, "ar member size overflows", offset);
        }

        auto next = checkedAdd(*dataEnd, member->size & 1U);
        if (!next || *next > fileSize) {
            return fail(ErrorKind::Truncated, "ar member data extends past end of file", offset);
        }
        offset = *next;
    }

    // NOTE: names_ may have reallocated while indexing, which invalidates the
    // string_view names stored in entries_, so rebind every view to its owner.
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        entries_[index].name = names_[index];
    }
    return {};
}

Result<void> Reader::addMember(const Member& member, std::uint64_t fileSize) {
    if (isStringTable(member.rawName)) {
        if (hasStringTable_) {
            return fail(ErrorKind::Malformed, "duplicate ar string table", member.headerOffset);
        }
        if (member.size > limits_.maxStringTableBytes) {
            return fail(
                ErrorKind::LimitExceeded,
                "ar string table exceeds limit",
                member.headerOffset
            );
        }

        auto bytes = checkedCast<std::size_t>(member.size);
        if (!bytes) {
            return fail(
                ErrorKind::LimitExceeded,
                "ar string table exceeds limit",
                member.headerOffset
            );
        }

        stringTable_.resize(*bytes);
        auto read =
            file_.readExactAt(member.dataOffset, std::as_writable_bytes(std::span(stringTable_)));
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        hasStringTable_ = true;
        return {};
    }

    if (isSymbolTable(member.rawName)) {
        return {};
    }

    auto dataOffset = member.dataOffset;
    auto size = member.size;

    std::string_view name = member.rawName;
    if (isGnuReference(name)) {
        auto resolved = resolveGnuName(member);
        if (!resolved) {
            return tl::unexpected<Error>(resolved.error());
        }
        name = *resolved;
    } else if (name.starts_with("#1/")) {
        auto extended = resolveBsdName(member, name, dataOffset, size);
        if (!extended) {
            return tl::unexpected<Error>(extended.error());
        }
    } else if (name.starts_with('/') || name.starts_with('#')) {
        return fail(ErrorKind::Unsupported, "unknown ar member name form", member.headerOffset);
    } else if (name.ends_with('/')) {
        name.remove_suffix(1);
    }

    return addNamed(member, name, dataOffset, size, fileSize);
}

Result<void> Reader::addNamed(
    const Member& member,
    std::string_view name,
    std::uint64_t dataOffset,
    std::uint64_t size,
    std::uint64_t fileSize
) {
    if (name.empty()) {
        return fail(ErrorKind::Malformed, "ar entry name is empty", member.headerOffset);
    }
    if (name.size() > limits_.maxNameBytes) {
        return fail(ErrorKind::LimitExceeded, "ar entry name exceeds limit", member.headerOffset);
    }
    if (name.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::Malformed, "ar entry name contains NUL", member.headerOffset);
    }
    if (size > limits_.maxEntryBytes) {
        return fail(ErrorKind::LimitExceeded, "ar entry exceeds size limit", member.headerOffset);
    }

    auto total = checkedAdd(totalBytes_, size);
    if (!total || *total > limits_.maxTotalBytes) {
        return fail(ErrorKind::LimitExceeded, "ar total size exceeds limit", member.headerOffset);
    }
    totalBytes_ = *total;

    auto end = checkedAdd(dataOffset, size);
    if (!end || *end > fileSize) {
        return fail(
            ErrorKind::Truncated,
            "ar member data extends past end of file",
            member.headerOffset
        );
    }

    names_.push_back(std::string(name));
    entries_.push_back(
        Entry{
            .name = names_.back(),
            .dataOffset = dataOffset,
            .size = size,
            .mtimeSeconds = member.mtimeSeconds,
            .uid = member.uid,
            .gid = member.gid,
            .mode = member.mode,
        }
    );
    return {};
}

Result<std::string_view> Reader::resolveGnuName(const Member& member) {
    if (!hasStringTable_) {
        return fail(
            ErrorKind::Malformed,
            "ar long name without a string table",
            member.headerOffset
        );
    }

    auto at = parseTableOffset(member.rawName, member.headerOffset);
    if (!at) {
        return tl::unexpected<Error>(at.error());
    }
    if (*at >= stringTable_.size()) {
        return fail(
            ErrorKind::Malformed,
            "ar string table offset out of range",
            member.headerOffset
        );
    }

    auto slash = stringTable_.find('/', static_cast<std::size_t>(*at));
    if (slash == std::string::npos) {
        return fail(
            ErrorKind::Malformed,
            "ar string table entry is not terminated",
            member.headerOffset
        );
    }

    auto name = std::string_view(stringTable_).substr(static_cast<std::size_t>(*at), slash - *at);
    if (name.size() > limits_.maxNameBytes) {
        return fail(ErrorKind::LimitExceeded, "ar entry name exceeds limit", member.headerOffset);
    }
    return name;
}

Result<void> Reader::resolveBsdName(
    const Member& member,
    std::string_view& name,
    std::uint64_t& dataOffset,
    std::uint64_t& size
) {
    std::uint64_t length = 0;
    for (char digit : name.substr(3)) {
        if (digit < '0' || digit > '9') {
            return fail(ErrorKind::Unsupported, "unknown ar member name form", member.headerOffset);
        }

        auto scaled = checkedMul(length, 10u);
        if (!scaled) {
            return fail(
                ErrorKind::Malformed,
                "ar extended name length overflows",
                member.headerOffset
            );
        }

        auto next = checkedAdd(*scaled, static_cast<std::uint64_t>(digit - '0'));
        if (!next) {
            return fail(
                ErrorKind::Malformed,
                "ar extended name length overflows",
                member.headerOffset
            );
        }
        length = *next;
    }
    if (length == 0 || length > limits_.maxNameBytes) {
        return fail(
            length == 0 ? ErrorKind::Malformed : ErrorKind::LimitExceeded,
            length == 0 ? "ar extended name is empty" : "ar entry name exceeds limit",
            member.headerOffset
        );
    }
    if (length > size) {
        return fail(
            ErrorKind::Malformed,
            "ar extended name exceeds member size",
            member.headerOffset
        );
    }

    auto bytes = checkedCast<std::size_t>(length);
    if (!bytes) {
        return fail(ErrorKind::LimitExceeded, "ar entry name exceeds limit", member.headerOffset);
    }

    extendedName_.resize(*bytes);

    auto read =
        file_.readExactAt(member.dataOffset, std::as_writable_bytes(std::span(extendedName_)));
    if (!read) {
        return tl::unexpected<Error>(read.error());
    }

    name = extendedName_;
    if (name.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::Malformed, "ar entry name contains NUL", member.headerOffset);
    }

    auto start = checkedAdd(dataOffset, length);
    if (!start) {
        return fail(ErrorKind::Malformed, "ar member offset overflows", member.headerOffset);
    }
    dataOffset = *start;
    size -= length;
    return Result<void>{};
}

}
