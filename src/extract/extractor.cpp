#include "extract/extractor.hpp"

#include <algorithm>
#include <functional>
#include <random>
#include <utility>

namespace bale {

namespace {

constexpr std::uint32_t permissionBits = 0777;
constexpr std::uint32_t allModeBits = 07777;
constexpr std::uint32_t defaultFileMode = 0644;
constexpr std::uint32_t defaultDirectoryMode = 0755;
constexpr std::uint32_t ownerAccess = 0700;
constexpr std::size_t minimumIdSlots = 64;
constexpr std::uint64_t emptyId = ~std::uint64_t{0};

[[nodiscard]] constexpr std::uint64_t mix(std::uint64_t value) {
    value += 0x9e3779b97f4a7c15;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9;
    value = (value ^ (value >> 27)) * 0x94d049bb133111eb;
    return value ^ (value >> 31);
}

[[nodiscard]] constexpr bool isAsciiAlpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

Result<void> checkComponent(std::string_view component) {
    if (component.empty()) {
        return fail(ErrorKind::UnsafePath, "empty path component");
    }
    if (component == "." || component == "..") {
        return fail(ErrorKind::UnsafePath, "dot path component");
    }
    if (component.size() > maxLeafBytes) {
        return fail(ErrorKind::UnsafePath, "path component too long for the target");
    }
    if (component.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "NUL byte in path");
    }
#ifdef _WIN32
    if (component.find_first_of("\\:") != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "backslash or colon in path component");
    }
#endif
    return {};
}

}

OsHandle::OsHandle(OsHandle&& other) noexcept : native_(std::exchange(other.native_, invalid)) {
}

OsHandle& OsHandle::operator=(OsHandle&& other) noexcept {
    if (this != &other) {
        reset();
        native_ = std::exchange(other.native_, invalid);
    }
    return *this;
}

OsHandle::~OsHandle() {
    reset();
}

PendingFile::PendingFile(PendingFile&& other) noexcept :
    owner_(other.owner_), directory_(std::move(other.directory_)), file_(std::move(other.file_)),
    metadata_(other.metadata_), tempName_(other.tempName_), leaf_(other.leaf_),
    leafSize_(other.leafSize_), state_(std::exchange(other.state_, State::Done)) {
}

PendingFile& PendingFile::operator=(PendingFile&& other) noexcept {
    if (this != &other) {
        discard();
        owner_ = other.owner_;
        directory_ = std::move(other.directory_);
        file_ = std::move(other.file_);
        metadata_ = other.metadata_;
        tempName_ = other.tempName_;
        leaf_ = other.leaf_;
        leafSize_ = other.leafSize_;
        state_ = std::exchange(other.state_, State::Done);
    }
    return *this;
}

PendingFile::~PendingFile() {
    discard();
}

void PendingFile::discard() {
    if (file_.valid() && state_ != State::Done) {
        owner_->removeTemporary(directory_, file_, tempName_.data());
    }
    file_.reset();
    directory_.reset();
}

Result<void> PendingFile::write(std::span<const std::byte> data) {
    if (state_ != State::Writing && state_ != State::Skipping) {
        return fail(ErrorKind::Io, "pending file is no longer writable");
    }

    auto charged = owner_->budget_.chargeBytes(data.size());
    if (!charged) {
        discard();
        state_ = State::Failed;
        return charged;
    }

    if (state_ == State::Skipping) {
        return {};
    }

    auto written = owner_->writeData(file_, data);
    if (!written) {
        discard();
        state_ = State::Failed;
    }
    return written;
}

Result<EntryResult> PendingFile::commit() {
    if (state_ == State::Skipping) {
        state_ = State::Done;
        return EntryResult{
            .outcome = EntryOutcome::Skipped,
            .reason = "target already exists",
        };
    }
    if (state_ != State::Writing) {
        return fail(ErrorKind::Io, "pending file cannot be committed");
    }

    auto finished = owner_->finishFile(*this);
    if (!finished || finished->outcome == EntryOutcome::Skipped) {
        discard();
    }

    state_ = finished ? State::Done : State::Failed;
    file_.reset();
    directory_.reset();
    return finished;
}

Extractor::Extractor(OsHandle root, const ExtractPolicy& policy) :
    root_(std::move(root)), policy_(policy), budget_(policy.limits) {
    std::random_device seed;
    tempSeed_ = (static_cast<std::uint64_t>(seed()) << 32) | seed();
    component_.reserve(maxLeafBytes + 1);
}

Result<Extractor::EntryPath> Extractor::splitPath(std::string_view path) {
    EntryPath result;
    std::size_t start = 0;
    while (true) {
        const std::size_t slash = path.find('/', start);
        const std::size_t end = slash == std::string_view::npos ? path.size() : slash;
        auto component = path.substr(start, end - start);

        auto checked = checkComponent(component);
        if (!checked) {
            return std::unexpected(checked.error());
        }

        if (slash == std::string_view::npos) {
            result.leaf = component;
            return result;
        }

        ++result.parentDepth;
        start = slash + 1;
    }
}

Result<Extractor::EntryPath> Extractor::beginEntry(const ArchivePath& path) {
    auto charged = budget_.chargeEntry();
    if (!charged) {
        return std::unexpected(charged.error());
    }

    auto split = splitPath(path.path);
    if (!split) {
        return split;
    }

    if (policy_.caseInsensitive) {
        const std::uint64_t exact = std::hash<std::string_view>{}(path.path);
        auto collision = caseFold_.insertOrFindCollision(path.path, exact);
        if (collision && *collision != exact) {
            return fail(ErrorKind::UnsafePath, "path collides with another entry ignoring case");
        }
    }
    return split;
}

Result<std::string_view>
Extractor::normalizeLinkTarget(std::string_view target, std::uint32_t parentDepth) {
    if (target.empty()) {
        return fail(ErrorKind::UnsafePath, "empty symlink target");
    }
    if (target.size() > policy_.limits.maxPathBytes) {
        return fail(ErrorKind::LimitExceeded, "symlink target exceeds maximum length");
    }
    if (target.find('\0') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "NUL byte in symlink target");
    }
    if (target.front() == '/' ||
        (target.size() >= 2 && isAsciiAlpha(target[0]) && target[1] == ':')) {
        return fail(ErrorKind::UnsafePath, "absolute symlink target");
    }
    if (target.find('\\') != std::string_view::npos) {
        return fail(ErrorKind::UnsafePath, "backslash in symlink target");
    }

    // SECURITY: a ".." after a name resolves physically, so stored targets keep every ".." leading.
    linkTarget_.clear();
    std::uint32_t ups = 0;
    std::size_t start = 0;
    while (start <= target.size()) {
        std::size_t end = target.find('/', start);
        if (end == std::string_view::npos) {
            end = target.size();
        }
        auto component = target.substr(start, end - start);
        start = end + 1;

        if (component.empty() || component == ".") {
            continue;
        }
        if (component != "..") {
            if (!linkTarget_.empty()) {
                linkTarget_.push_back('/');
            }
            linkTarget_.append(component);
            continue;
        }

        if (!linkTarget_.empty()) {
            const std::size_t slash = linkTarget_.rfind('/');
            linkTarget_.resize(slash == std::string::npos ? 0 : slash);
            continue;
        }
        if (ups == parentDepth) {
            return fail(ErrorKind::UnsafePath, "symlink target escapes the extraction root");
        }
        ++ups;
    }

    if (ups > 0) {
        linkTarget_.insert(0, std::size_t{ups} * 3 - (linkTarget_.empty() ? 1 : 0), '/');
        for (std::uint32_t i = 0; i < ups; ++i) {
            linkTarget_[std::size_t{i} * 3] = '.';
            linkTarget_[std::size_t{i} * 3 + 1] = '.';
        }
    } else if (linkTarget_.empty()) {
        linkTarget_ = ".";
    }
    return linkTarget_;
}

std::uint32_t Extractor::fileMode(const EntryMetadata& metadata) const {
    const std::uint32_t allowed = policy_.restoreSpecialModeBits ? allModeBits : permissionBits;
    return metadata.mode.value_or(defaultFileMode) & allowed & ~policy_.umask;
}

std::uint32_t Extractor::directoryMode(const EntryMetadata& metadata) const {
    const std::uint32_t allowed = policy_.restoreSpecialModeBits ? allModeBits : permissionBits;
    const std::uint32_t mode = metadata.mode.value_or(defaultDirectoryMode) & allowed;

    return (mode & ~policy_.umask) | ownerAccess;
}

void Extractor::nextTempName(TempName& name) {
    static constexpr std::string_view prefix = ".bale-";
    static constexpr std::string_view digits = "0123456789abcdef";

    std::uint64_t value = mix(tempSeed_ + ++tempCounter_);
    std::size_t at = 0;
    for (char c : prefix) {
        name[at++] = c;
    }
    for (int i = 0; i < 16; ++i) {
        name[at++] = digits[value & 0xF];
        value >>= 4;
    }
    name[at] = '\0';
}

Result<EntryResult>
Extractor::skipOrRefuseSpecialFile(const ArchivePath& path, SpecialFileKind kind) {
    auto entry = beginEntry(path);
    if (!entry) {
        return std::unexpected(entry.error());
    }

    if (policy_.specialFiles == SpecialFilePolicy::Refuse) {
        if (kind == SpecialFileKind::Fifo) {
            return fail(ErrorKind::Unsupported, "FIFO entries are refused");
        }
        return fail(ErrorKind::Unsupported, "device and socket entries are refused");
    }
    return EntryResult{
        .outcome = EntryOutcome::Skipped,
        .reason = "device nodes, FIFOs and sockets are never created",
    };
}

void Extractor::deferDirectoryTime(
    const ArchivePath& path,
    FileId id,
    std::int64_t mtimeNanoseconds
) {
    deferredTimes_.push_back(
        DeferredTime{
            .id = id,
            .mtimeNanoseconds = mtimeNanoseconds,
            .pathOffset = deferredPaths_.size(),
            .pathSize = static_cast<std::uint32_t>(path.path.size()),
            .depth = path.depth,
        }
    );
    deferredPaths_.append(path.path);
}

Result<void> Extractor::finish() {
    std::ranges::stable_sort(deferredTimes_, std::ranges::greater{}, &DeferredTime::depth);

    Result<void> result;
    for (const DeferredTime& time : deferredTimes_) {
        const std::string_view path =
            std::string_view(deferredPaths_).substr(time.pathOffset, time.pathSize);
        auto applied = applyDeferredTime(path, time);
        if (!applied && result) {
            result = applied;
        }
    }

    deferredTimes_.clear();
    deferredPaths_.clear();
    return result;
}

void Extractor::FileIdSet::insert(FileId id) {
    if ((size_ + 1) * 2 > slots_.size()) {
        grow();
    }

    FileId& slot = slots_[slotFor(id)];
    if (slot.inode == emptyId) {
        slot = id;
        ++size_;
    }
}

bool Extractor::FileIdSet::contains(FileId id) const {
    if (slots_.empty()) {
        return false;
    }
    return slots_[slotFor(id)] == id;
}

std::size_t Extractor::FileIdSet::slotFor(FileId id) const {
    const std::size_t mask = slots_.size() - 1;
    std::size_t index = mix(id.inode ^ mix(id.device)) & mask;
    while (slots_[index].inode != emptyId && slots_[index] != id) {
        index = (index + 1) & mask;
    }
    return index;
}

void Extractor::FileIdSet::grow() {
    std::vector<FileId> old = std::move(slots_);
    slots_.assign(
        old.empty() ? minimumIdSlots : old.size() * 2,
        FileId{
            .device = emptyId,
            .inode = emptyId,
        }
    );

    for (const FileId& id : old) {
        if (id.inode != emptyId) {
            slots_[slotFor(id)] = id;
        }
    }
}

}
