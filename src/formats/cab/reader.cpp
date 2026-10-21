#include "formats/cab/reader.hpp"

#include "codecs/decoders.hpp"

#include <array>
#include <utility>

namespace bale::cab {

Result<Reader> Reader::open(File file, const Limits& limits) {
    auto size = file.size();
    if (!size) {
        return std::unexpected(size.error());
    }
    if (*size < signature.size()) {
        return fail(ErrorKind::Malformed, "not a cabinet archive");
    }

    std::array<std::byte, 8> head{};
    auto headRead = file.readExactAt(0, head);
    if (!headRead) {
        return std::unexpected(headRead.error());
    }
    if (!looksLikeCab(head)) {
        return fail(ErrorKind::Malformed, "not a cabinet archive");
    }

    auto model = parseCabinet(file, *size, limits);
    if (!model) {
        return std::unexpected(model.error());
    }
    if (model->hasPrev || model->hasNext) {
        return fail(ErrorKind::Unsupported, "multi-cabinet sets are not supported");
    }
    for (const auto& entry : model->files) {
        if (entry.spanned) {
            return fail(ErrorKind::Unsupported, "multi-cabinet sets are not supported");
        }
    }

    Reader reader(std::move(file), limits);
    reader.model_ = std::move(*model);
    reader.entries_.reserve(reader.model_.files.size());
    for (const auto& fileEntry : reader.model_.files) {
        reader.entries_.push_back(
            Entry{
                .name = fileEntry.name,
                .size = fileEntry.size,
                .folder = fileEntry.folder,
                .folderOffset = fileEntry.folderOffset,
                .mtimeSeconds = fileEntry.mtimeSeconds,
                .mode = fileEntry.mode,
                .directory = fileEntry.directory,
            }
        );
    }
    return reader;
}

Result<Session*> Reader::sessionFor(const Entry& entry) {
    if (entry.folder >= model_.folders.size()) {
        return fail(ErrorKind::Malformed, "cabinet entry references no folder");
    }
    if (entry.size > limits_.maxEntryBytes) {
        return fail(ErrorKind::LimitExceeded, "cabinet entry exceeds size limit");
    }

    if (active_ && active_->folder == entry.folder &&
        active_->session.position() <= entry.folderOffset) {
        return &active_->session;
    }

    const Folder& folder = model_.folders[entry.folder];
    if (folder.method == methodMszip && !inflater_) {
        auto created = Inflater::create();
        if (!created) {
            return std::unexpected(created.error());
        }
        inflater_.emplace(std::move(*created));
    }

    auto duplicate = file_.duplicate();
    if (!duplicate) {
        return std::unexpected(duplicate.error());
    }

    auto session = Session::start(std::move(*duplicate), folder, inflater_ ? &*inflater_ : nullptr);
    if (!session) {
        return std::unexpected(session.error());
    }

    active_.emplace(Active{.folder = entry.folder, .session = std::move(*session)});
    return &active_->session;
}

}