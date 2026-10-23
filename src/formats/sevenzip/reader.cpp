#include "formats/sevenzip/reader.hpp"

#include "base/checked.hpp"

#include <algorithm>
#include <utility>

namespace bale::sevenzip {

namespace {

constexpr std::uint8_t encodedTag = 0x17;
constexpr std::size_t decodeChunkSize = std::size_t{64} * 1024;

Result<std::vector<std::byte>> concatPacks(
    const File& file,
    const Model& outer,
    std::uint64_t packBase,
    std::uint64_t fileSize,
    const Limits& limits
) {
    std::uint64_t total = 0;
    for (const auto& pack : outer.packs) {
        auto next = checkedAdd(total, pack.size);
        if (!next) {
            return fail(ErrorKind::Malformed, "7z header pack size overflows");
        }
        total = *next;
    }
    if (total > limits.maxHeaderBytes) {
        return fail(ErrorKind::LimitExceeded, "7z header exceeds limit");
    }

    auto bytes = checkedCast<std::size_t>(total);
    if (!bytes) {
        return fail(ErrorKind::LimitExceeded, "7z header exceeds limit");
    }

    std::vector<std::byte> header(*bytes);
    std::uint64_t position = packBase;
    std::size_t filled = 0;
    for (const auto& pack : outer.packs) {
        auto packBytes = checkedCast<std::size_t>(pack.size);
        if (!packBytes) {
            return fail(ErrorKind::LimitExceeded, "7z header exceeds limit");
        }

        auto end = checkedAdd(position, pack.size);
        if (!end || *end > fileSize) {
            return fail(ErrorKind::Truncated, "7z pack data extends past end of file", position);
        }

        auto chunk = std::span(header).subspan(filled, *packBytes);
        auto read = file.readExactAt(position, chunk);
        if (!read) {
            return tl::unexpected<Error>(read.error());
        }
        if (pack.crc && Crc32::of(chunk) != *pack.crc) {
            return fail(ErrorKind::Integrity, "7z pack CRC-32 mismatch", position);
        }

        position = *end;
        filled += *packBytes;
    }
    return header;
}

Result<std::vector<std::byte>> decodeHeaderFolder(
    File file,
    const FolderPlan& plan,
    const Limits& limits,
    Inflater* inflater,
    Bzip2Decoder* bzip2
) {
    if (plan.codec.encrypted) {
        return fail(ErrorKind::PasswordRequired, "7z header is encrypted");
    }
    if (plan.unpackSize > limits.maxHeaderBytes) {
        return fail(ErrorKind::LimitExceeded, "7z header exceeds limit");
    }

    auto session = FolderSession::start(std::move(file), plan, limits, inflater, bzip2);
    if (!session) {
        return tl::unexpected<Error>(session.error());
    }

    auto headerBytes = checkedCast<std::size_t>(plan.unpackSize);
    if (!headerBytes) {
        return fail(ErrorKind::LimitExceeded, "7z header exceeds limit");
    }

    std::vector<std::byte> header;
    header.reserve(*headerBytes);
    std::vector<std::byte> scratch(decodeChunkSize);
    auto started = session->startEntry(0, plan.unpackSize, std::nullopt, scratch);
    if (!started) {
        return tl::unexpected<Error>(started.error());
    }

    while (true) {
        auto chunk = session->nextChunk();
        if (!chunk) {
            return tl::unexpected<Error>(chunk.error());
        }
        if (chunk->empty()) {
            return header;
        }
        header.insert(header.end(), chunk->begin(), chunk->end());
    }
}

Result<std::vector<std::byte>>
decodeHeader(const File& file, Signature signature, const Limits& limits, std::uint64_t fileSize) {
    if (signature.bytes.empty() || signature.bytes.front() != std::byte{encodedTag}) {
        return std::move(signature.bytes);
    }

    auto outer = parseHeader(signature.bytes, signature.headerOffset, limits);
    if (!outer) {
        return tl::unexpected<Error>(outer.error());
    }
    if (outer->folders.size() > 1) {
        return fail(
            ErrorKind::Unsupported,
            "7z encoded header uses multiple folders",
            signature.headerOffset
        );
    }

    auto packBase = checkedAdd(std::uint64_t{signatureSize}, outer->packPos);
    if (!packBase) {
        return fail(ErrorKind::Malformed, "7z header pack offset overflows");
    }

    if (outer->folders.empty()) {
        return concatPacks(file, *outer, *packBase, fileSize, limits);
    }

    auto plan = resolveFolder(outer->folders.front(), outer->packs, 0, *packBase, fileSize, limits);
    if (!plan) {
        return tl::unexpected<Error>(plan.error());
    }
    if (plan->failed()) {
        return fail(
            ErrorKind::Unsupported,
            "7z header codec is not supported",
            signature.headerOffset
        );
    }

    std::optional<Inflater> inflater;
    std::optional<Bzip2Decoder> bzip2;
    if (plan->codec.codec == Codec::Deflate) {
        auto created = Inflater::create();
        if (!created) {
            return tl::unexpected<Error>(created.error());
        }
        inflater.emplace(std::move(*created));
    }
    if (plan->codec.codec == Codec::Bzip2) {
        auto created = Bzip2Decoder::create();
        if (!created) {
            return tl::unexpected<Error>(created.error());
        }
        bzip2.emplace(std::move(*created));
    }

    auto packed = file.duplicate();
    if (!packed) {
        return tl::unexpected<Error>(packed.error());
    }
    return decodeHeaderFolder(
        std::move(*packed),
        *plan,
        limits,
        inflater ? &*inflater : nullptr,
        bzip2 ? &*bzip2 : nullptr
    );
}

}

Result<Reader> Reader::open(File file, const Limits& limits) {
    auto fileSize = file.size();
    if (!fileSize) {
        return tl::unexpected<Error>(fileSize.error());
    }

    auto signature = readSignature(file, limits);
    if (!signature) {
        return tl::unexpected<Error>(signature.error());
    }

    auto headerBytes = decodeHeader(file, std::move(*signature), limits, *fileSize);
    if (!headerBytes) {
        return tl::unexpected<Error>(headerBytes.error());
    }

    auto model = parseHeader(*headerBytes, signature->headerOffset, limits);
    if (!model) {
        return tl::unexpected<Error>(model.error());
    }

    auto packBase = checkedAdd(std::uint64_t{signatureSize}, model->packPos);
    if (!packBase) {
        return fail(ErrorKind::Malformed, "7z pack offset overflows");
    }

    Reader reader(std::move(file), limits);

    std::uint64_t firstPackStream = 0;
    std::uint64_t packPosition = *packBase;
    for (const auto& folder : model->folders) {
        auto folderPackEnd = checkedAdd(firstPackStream, folder.numPackedStreams);
        if (!folderPackEnd || *folderPackEnd > model->packs.size()) {
            return fail(ErrorKind::Malformed, "7z folder references no pack stream");
        }

        auto plan =
            resolveFolder(folder, model->packs, firstPackStream, packPosition, *fileSize, limits);
        for (std::uint64_t index = firstPackStream; index < *folderPackEnd; ++index) {
            auto next = checkedAdd(packPosition, model->packs[index].size);
            if (!next) {
                return fail(ErrorKind::Malformed, "7z pack offset overflows");
            }
            packPosition = *next;
        }
        firstPackStream = *folderPackEnd;
        reader.plans_.push_back(std::move(plan));
    }
    if (firstPackStream != model->packs.size()) {
        return fail(ErrorKind::Malformed, "7z folder pack mapping does not match");
    }
    if (model->hasStreams && model->folders.empty() && !model->packs.empty()) {
        return fail(ErrorKind::Malformed, "7z pack data without folders");
    }

    std::uint64_t substreams = 0;
    for (const auto& folderStreams : model->substreams) {
        auto next = checkedAdd(substreams, folderStreams.size());
        if (!next || next > limits.maxEntries) {
            return fail(ErrorKind::LimitExceeded, "7z stream count exceeds limit");
        }
        substreams = *next;
    }

    std::uint64_t withStreams = 0;
    for (const auto& meta : model->files) {
        if (meta.hasStream && !meta.anti) {
            ++withStreams;
        }
    }
    if (withStreams != substreams) {
        return fail(ErrorKind::Malformed, "7z file streams do not match files");
    }

    reader.names_.reserve(model->files.size());
    reader.entries_.reserve(model->files.size());

    std::vector<std::uint64_t> offsets(model->folders.size(), 0);
    std::vector<std::size_t> cursors(model->folders.size(), 0);
    std::size_t packedFolder = 0;
    for (auto& meta : model->files) {
        if (meta.anti) {
            continue;
        }

        reader.names_.push_back(std::move(meta.name));
        std::string_view name = reader.names_.back();
        if (name.empty()) {
            return fail(ErrorKind::Malformed, "7z entry name is empty");
        }

        if (!meta.hasStream) {
            reader.entries_.push_back(
                Entry{
                    .name = name,
                    .size = 0,
                    .folder = std::nullopt,
                    .offset = 0,
                    .crc = std::nullopt,
                    .mtimeNanoseconds = meta.mtimeNanoseconds,
                    .mode = meta.mode,
                    .directory = !meta.emptyFile,
                }
            );
            if (meta.startPos && *meta.startPos != 0) {
                return fail(ErrorKind::Unsupported, "7z start positions are not supported");
            }
            continue;
        }

        while (packedFolder < model->substreams.size() &&
               cursors[packedFolder] >= model->substreams[packedFolder].size()) {
            ++packedFolder;
        }
        if (packedFolder >= model->substreams.size()) {
            return fail(ErrorKind::Malformed, "7z file streams do not match files");
        }

        const SubStream& stream = model->substreams[packedFolder][cursors[packedFolder]];
        if (meta.startPos.value_or(offsets[packedFolder]) != offsets[packedFolder]) {
            return fail(ErrorKind::Unsupported, "7z start positions are not supported");
        }

        auto end = checkedAdd(offsets[packedFolder], stream.size);
        if (!end) {
            return fail(ErrorKind::Malformed, "7z substream offsets overflow");
        }

        reader.entries_.push_back(
            Entry{
                .name = name,
                .size = stream.size,
                .folder = packedFolder,
                .offset = offsets[packedFolder],
                .crc = stream.crc,
                .mtimeNanoseconds = meta.mtimeNanoseconds,
                .mode = meta.mode,
            }
        );
        offsets[packedFolder] = *end;
        ++cursors[packedFolder];
    }
    return reader;
}

Result<FolderSession*> Reader::sessionFor(const Entry& entry) {
    if (!entry.folder) {
        return fail(ErrorKind::Malformed, "7z entry has no folder");
    }
    if (*entry.folder >= plans_.size()) {
        return fail(ErrorKind::Malformed, "7z entry references no folder");
    }

    auto& stored = plans_[*entry.folder];
    if (!stored) {
        return tl::unexpected<Error>(stored.error());
    }
    if (stored->codec.encrypted) {
        return fail(ErrorKind::PasswordRequired, "7z entry is encrypted");
    }
    if (stored->failed()) {
        return fail(ErrorKind::Unsupported, stored->failure());
    }
    if (entry.size > limits_.maxEntryBytes) {
        return fail(ErrorKind::LimitExceeded, "7z entry exceeds size limit");
    }

    if (active_ && active_->folder == *entry.folder &&
        active_->session.position() <= entry.offset) {
        return &active_->session;
    }

    if (stored->codec.codec == Codec::Deflate && !inflater_) {
        auto created = Inflater::create();
        if (!created) {
            return tl::unexpected<Error>(created.error());
        }
        inflater_.emplace(std::move(*created));
    }
    if (stored->codec.codec == Codec::Bzip2 && !bzip2_) {
        auto created = Bzip2Decoder::create();
        if (!created) {
            return tl::unexpected<Error>(created.error());
        }
        bzip2_.emplace(std::move(*created));
    }

    auto packed = file_.duplicate();
    if (!packed) {
        return tl::unexpected<Error>(packed.error());
    }

    auto session = FolderSession::start(
        std::move(*packed),
        *stored,
        limits_,
        inflater_ ? &*inflater_ : nullptr,
        bzip2_ ? &*bzip2_ : nullptr
    );
    if (!session) {
        return tl::unexpected<Error>(session.error());
    }

    active_.emplace(Active{.folder = *entry.folder, .session = std::move(*session)});
    return &active_->session;
}

bool looksLikeSevenZip(std::span<const std::byte> head) {
    return head.size() >= signatureMagic.size() &&
        std::ranges::equal(signatureMagic, head.first(signatureMagic.size()));
}

}
