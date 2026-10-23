#pragma once

#include "wim_builder.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

namespace bale::wim::test {

namespace {

using Bytes = std::vector<std::byte>;

void put16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>(value & 0xFF));
    out.push_back(static_cast<std::byte>((value >> 8) & 0xFF));
}

void put32(Bytes& out, std::uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xFF));
    }
}

void put64(Bytes& out, std::uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<std::byte>((value >> shift) & 0xFF));
    }
}

void putHash(Bytes& out, const std::array<std::byte, 20>& hash) {
    out.insert(out.end(), hash.begin(), hash.end());
}

// NOTE: test-only stand-in for SHA-1: lookups match dentries to blobs
// opaquely, so any deterministic nonzero digest works. Golden content
// coverage uses real hashes from tests/formats/wim/data instead.
std::array<std::byte, 20> fakeHash(const Bytes& data) {
    std::uint64_t folded = 0xcbf29ce484222325ULL;
    for (std::byte unit : data) {
        folded ^= static_cast<std::uint64_t>(unit);
        folded *= 0x100000001b3ULL;
    }
    folded ^= data.size() + 0x9e3779b97f4a7c15ULL;
    std::array<std::byte, 20> hash{};
    for (std::size_t index = 0; index < hash.size(); ++index) {
        hash[index] = static_cast<std::byte>((folded >> ((index % 8) * 8)) & 0xFF);
        folded = folded * 6364136223846793005ULL + 1442695040888963407ULL;
    }
    if (std::all_of(hash.begin(), hash.end(), [](std::byte b) {
            return b == std::byte{0};
        })) {
        hash[0] = std::byte{1};
    }
    return hash;
}

Bytes utf16(const std::string& text) {
    Bytes out;
    for (std::byte unit : std::as_bytes(std::span(text))) {
        out.push_back(unit);
        out.push_back(std::byte{0});
    }
    return out;
}

Bytes makeDentry(
    const std::string& name,
    std::uint32_t attrs,
    const std::array<std::byte, 20>& mainHash,
    std::uint32_t reparseTag,
    std::uint64_t group,
    const std::vector<std::pair<Bytes, Bytes>>& extras
) {
    Bytes nameRaw = name.empty() ? Bytes{} : utf16(name);
    Bytes out;
    put64(out, 0);
    put32(out, attrs);
    put32(out, 0xFFFFFFFF);
    put64(out, 0);
    put64(out, 0);
    put64(out, 0);
    put64(out, 132000000000000000ULL);
    put64(out, 132000000000000000ULL);
    put64(out, 132000000000000000ULL);
    putHash(out, mainHash);
    put32(out, 0);
    if (reparseTag != 0) {
        put32(out, reparseTag);
        put16(out, 0);
        put16(out, 0);
    } else {
        put64(out, group);
    }
    put16(out, static_cast<std::uint16_t>(extras.size()));
    put16(out, 0);
    put16(out, static_cast<std::uint16_t>(nameRaw.size()));
    out.insert(out.end(), nameRaw.begin(), nameRaw.end());
    if (!nameRaw.empty()) {
        out.push_back(std::byte{0});
        out.push_back(std::byte{0});
    }
    while (out.size() % 8 != 0) {
        out.push_back(std::byte{0});
    }
    out[0] = static_cast<std::byte>(out.size() & 0xFF);
    out[1] = static_cast<std::byte>((out.size() >> 8) & 0xFF);
    for (const auto& [hash, streamName] : extras) {
        Bytes entry;
        put64(entry, 0);
        put64(entry, 0);
        entry.insert(entry.end(), hash.begin(), hash.end());
        put16(entry, static_cast<std::uint16_t>(streamName.size()));
        entry.insert(entry.end(), streamName.begin(), streamName.end());
        if (!streamName.empty()) {
            entry.push_back(std::byte{0});
            entry.push_back(std::byte{0});
        }
        while (entry.size() % 8 != 0) {
            entry.push_back(std::byte{0});
        }
        entry[0] = static_cast<std::byte>(entry.size() & 0xFF);
        out.insert(out.end(), entry.begin(), entry.end());
    }
    return out;
}

struct BuiltMeta {
    Bytes bytes;
};

BuiltMeta buildMeta(
    const TestImage& image,
    std::map<std::vector<std::byte>, std::array<std::byte, 20>>& digests,
    const std::map<std::string, std::string>& subdirOverride
) {
    auto digestOf = [&](const Bytes& data) -> std::array<std::byte, 20> {
        if (data.empty()) {
            return {};
        }
        auto known = digests.find(data);
        if (known != digests.end()) {
            return known->second;
        }
        auto hash = fakeHash(data);
        digests[data] = hash;
        return hash;
    };

    std::vector<TestFile> all = image.files;
    for (const TestFile& file : image.files) {
        std::string rest = file.path;
        std::string prefix;
        while (true) {
            auto slash = rest.find('/');
            if (slash == std::string::npos) {
                break;
            }
            std::string ancestor =
                prefix.empty() ? rest.substr(0, slash) : prefix + '/' + rest.substr(0, slash);
            bool known = false;
            for (const TestFile& other : all) {
                if (other.path == ancestor) {
                    known = true;
                    break;
                }
            }
            if (!known) {
                TestFile synthetic;
                synthetic.path = ancestor;
                synthetic.attrs = 0x10;
                all.push_back(synthetic);
            }
            prefix = ancestor;
            rest = rest.substr(slash + 1);
        }
    }

    std::map<std::string, std::vector<const TestFile*>> children;
    for (const TestFile& file : all) {
        auto slash = file.path.rfind('/');
        std::string parent = slash == std::string::npos ? "" : file.path.substr(0, slash);
        children[parent].push_back(&file);
    }

    auto isDir = [](const TestFile* file) {
        return file->data.empty() && (file->attrs & 0x10) != 0 && file->reparseTag == 0;
    };

    std::vector<std::string> layout{""};
    for (std::size_t index = 0; index < layout.size(); ++index) {
        std::vector<std::string> members;
        auto found = children.find(layout[index]);
        if (found != children.end()) {
            for (const TestFile* file : found->second) {
                if (isDir(file) &&
                    std::find(layout.begin(), layout.end(), file->path) == layout.end()) {
                    members.push_back(file->path);
                }
            }
        }
        std::sort(members.begin(), members.end());
        layout.insert(layout.end(), members.begin(), members.end());
    }

    struct Block {
        Bytes bytes;
        std::vector<std::pair<std::size_t, std::string>> subdirs;
    };
    std::map<std::string, Block> blocks;
    for (const std::string& parent : layout) {
        Block block;
        if (parent.empty()) {
            block.bytes = makeDentry("", 0x10, {}, 0, 0, {});
        }
        auto found = children.find(parent);
        std::vector<const TestFile*> files;
        if (found != children.end()) {
            files = found->second;
        }
        std::sort(files.begin(), files.end(), [](const TestFile* a, const TestFile* b) {
            return a->path < b->path;
        });
        for (const TestFile* file : files) {
            auto slash = file->path.rfind('/');
            std::string leaf =
                slash == std::string::npos ? file->path : file->path.substr(slash + 1);
            std::array<std::byte, 20> main{};
            std::vector<std::pair<Bytes, Bytes>> extras;
            if (file->reparseTag != 0) {
                main = digestOf(file->reparseData);
            } else if (!isDir(file)) {
                main = digestOf(file->data);
            }
            for (const auto& [streamName, streamData] : file->extras) {
                auto hash = digestOf(streamData);
                extras.emplace_back(Bytes(hash.begin(), hash.end()), utf16(streamName));
            }
            Bytes dentry =
                makeDentry(leaf, file->attrs, main, file->reparseTag, file->group, extras);
            block.subdirs.emplace_back(block.bytes.size(), file->path);
            block.bytes.insert(block.bytes.end(), dentry.begin(), dentry.end());
        }
        for (int pad = 0; pad < 8; ++pad) {
            block.bytes.push_back(std::byte{0});
        }
        blocks[parent] = std::move(block);
    }

    std::map<std::string, std::uint64_t> offsets;
    std::uint64_t cursor = 8;
    for (const std::string& parent : layout) {
        offsets[parent] = cursor;
        cursor += blocks[parent].bytes.size();
    }
    // NOTE: the root dentry lives at the head of the "" block; its subdir
    // points just past itself.
    {
        Block& root = blocks[""];
        std::uint64_t sub = offsets[""] + 104;
        for (int shift = 0; shift < 64; shift += 8) {
            root.bytes[16 + static_cast<std::size_t>(shift)] =
                static_cast<std::byte>((sub >> shift) & 0xFF);
        }
    }
    for (const std::string& parent : layout) {
        Block& block = blocks[parent];
        for (const auto& [at, full] : block.subdirs) {
            std::uint64_t sub = 0;
            auto forced = subdirOverride.find(full);
            if (forced != subdirOverride.end()) {
                auto target = offsets.find(forced->second);
                sub = target == offsets.end() ? 0xFFFFFFFFFFFFFFFFULL : target->second;
            } else {
                auto target = offsets.find(full);
                if (target != offsets.end() && target->second != offsets[parent]) {
                    bool dir = false;
                    auto found = children.find(parent);
                    if (found != children.end()) {
                        for (const TestFile* file : found->second) {
                            if (file->path == full && isDir(file)) {
                                dir = true;
                            }
                        }
                    }
                    if (dir) {
                        sub = target->second;
                    }
                }
            }
            for (int shift = 0; shift < 64; shift += 8) {
                block.bytes[at + 16 + static_cast<std::size_t>(shift) / 8] =
                    static_cast<std::byte>((sub >> shift) & 0xFF);
            }
        }
    }

    Bytes out;
    put32(out, 8);
    put32(out, 0);
    for (const std::string& parent : layout) {
        const Bytes& block = blocks[parent].bytes;
        out.insert(out.end(), block.begin(), block.end());
    }
    BuiltMeta meta;
    meta.bytes = std::move(out);
    return meta;
}

}

inline std::vector<std::byte> buildWim(const TestWim& spec) {
    std::map<std::vector<std::byte>, std::array<std::byte, 20>> digests;
    std::vector<BuiltMeta> metas;
    for (const TestImage& image : spec.images) {
        metas.push_back(buildMeta(image, digests, spec.subdirOverride));
        digests[metas.back().bytes] = fakeHash(metas.back().bytes);
    }

    std::set<std::vector<std::byte>> compressed;
    if (!spec.compressedBlobs.empty()) {
        for (const TestImage& image : spec.images) {
            for (const TestFile& file : image.files) {
                for (const Bytes& marker : spec.compressedBlobs) {
                    if (file.data == marker) {
                        auto known = digests.find(marker);
                        if (known != digests.end()) {
                            compressed.insert(marker);
                        }
                    }
                }
            }
        }
    }
    std::map<std::vector<std::byte>, std::vector<std::vector<std::byte>>> lzx;
    for (const auto& [plain, stored] : spec.lzxBlobs) {
        lzx[plain] = stored;
    }

    Bytes blobs;
    Bytes table;
    std::uint64_t cursor = 208;
    std::vector<std::uint64_t> metaOffsets;
    auto emit = [&](const Bytes& body,
                    const std::array<std::byte, 20>& hash,
                    std::uint8_t flags,
                    std::uint64_t uncompressed) {
        std::uint64_t at = cursor;
        blobs.insert(blobs.end(), body.begin(), body.end());
        cursor += body.size();
        for (std::size_t index = 0; index < 7; ++index) {
            table.push_back(static_cast<std::byte>((body.size() >> (index * 8)) & 0xFF));
        }
        table.push_back(static_cast<std::byte>(flags));
        put64(table, at);
        put64(table, uncompressed);
        put16(table, 1);
        put32(table, 1);
        table.insert(table.end(), hash.begin(), hash.end());
        return at;
    };

    std::map<std::vector<std::byte>, std::array<std::byte, 20>> ordered(digests);
    std::set<std::vector<std::byte>> metaSet;
    for (const BuiltMeta& meta : metas) {
        metaSet.insert(meta.bytes);
    }
    std::set<std::vector<std::byte>> solidMembers;
    if (spec.solid) {
        for (const auto& [data, hash] : ordered) {
            if (!metaSet.contains(data) && !data.empty()) {
                solidMembers.insert(data);
            }
        }
    }
    for (const auto& [data, hash] : ordered) {
        if (solidMembers.contains(data) || metaSet.contains(data)) {
            continue;
        }
        if (compressed.contains(data)) {
            std::uint64_t chunks = (data.size() + spec.chunkSize - 1) / spec.chunkSize;
            Bytes body;
            for (std::uint64_t chunk = 1; chunk < chunks; ++chunk) {
                std::uint64_t offset = chunk * spec.chunkSize;
                if (spec.corruptTable) {
                    offset = (chunks - chunk) * spec.chunkSize;
                }
                for (int shift = 0; shift < 32; shift += 8) {
                    body.push_back(static_cast<std::byte>((offset >> shift) & 0xFF));
                }
            }
            for (std::uint64_t chunk = 0; chunk < chunks; ++chunk) {
                body.push_back(std::byte{0});
            }
            emit(body, hash, 0x04, data.size());
            continue;
        }
        auto coded = lzx.find(data);
        if (coded != lzx.end()) {
            // NOTE: real compressed body: chunk table of cumulative stored
            // offsets followed by the stored chunks. The test pins the
            // chunk count against ceil(plain/chunkSize) before building.
            Bytes body;
            std::uint64_t offset = 0;
            for (std::size_t chunk = 1; chunk < coded->second.size(); ++chunk) {
                offset += coded->second[chunk - 1].size();
                for (int shift = 0; shift < 32; shift += 8) {
                    body.push_back(static_cast<std::byte>((offset >> shift) & 0xFF));
                }
            }
            for (const auto& stored : coded->second) {
                body.insert(body.end(), stored.begin(), stored.end());
            }
            emit(body, hash, 0x04, data.size());
            continue;
        }
        emit(data, hash, 0x00, data.size());
    }
    if (spec.solid) {
        std::vector<std::vector<std::byte>> members(solidMembers.begin(), solidMembers.end());
        std::uint64_t total = 0;
        for (const auto& data : members) {
            total += data.size();
        }
        Bytes body;
        put64(body, total);
        put32(body, 32768);
        put32(body, 0);
        for (const auto& data : members) {
            put32(body, static_cast<std::uint32_t>(data.size()));
        }
        for (const auto& data : members) {
            body.insert(body.end(), data.begin(), data.end());
        }
        std::uint64_t at = cursor;
        blobs.insert(blobs.end(), body.begin(), body.end());
        cursor += body.size();
        auto marker = [&](std::uint64_t size,
                          std::uint8_t flags,
                          std::uint64_t offset,
                          std::uint64_t uncompressed,
                          const std::array<std::byte, 20>& hash) {
            for (std::size_t index = 0; index < 7; ++index) {
                table.push_back(static_cast<std::byte>((size >> (index * 8)) & 0xFF));
            }
            table.push_back(static_cast<std::byte>(flags));
            put64(table, offset);
            put64(table, uncompressed);
            put16(table, 1);
            put32(table, 1);
            table.insert(table.end(), hash.begin(), hash.end());
        };
        marker(body.size(), 0x10, at, 0x100000000ULL, {});
        std::uint64_t base = 0;
        for (const auto& data : members) {
            marker(data.size(), 0x10, base, 0, digests[data]);
            base += data.size();
        }
    }
    for (const BuiltMeta& meta : metas) {
        std::array<std::byte, 20> hash{};
        for (const auto& [data, digest] : digests) {
            if (data == meta.bytes) {
                hash = digest;
            }
        }
        metaOffsets.push_back(emit(meta.bytes, hash, 0x02, meta.bytes.size()));
    }

    Bytes xml = {std::byte{0xFF}, std::byte{0xFE}};
    std::string text = "<WIM>";
    for (std::size_t index = 0; index < spec.images.size(); ++index) {
        text += "<IMAGE INDEX=\"" + std::to_string(index + 1) + "\"><NAME>image-" +
            std::to_string(index + 1) + "</NAME></IMAGE>";
    }
    text += "</WIM>";
    for (char unit : text) {
        xml.push_back(static_cast<std::byte>(unit));
        xml.push_back(std::byte{0});
    }

    std::uint64_t lookupAt = cursor;
    std::uint64_t xmlAt = cursor + table.size();

    Bytes header;
    header.insert(
        header.end(),
        {std::byte{'M'},
         std::byte{'S'},
         std::byte{'W'},
         std::byte{'I'},
         std::byte{'M'},
         std::byte{0},
         std::byte{0},
         std::byte{0}}
    );
    put32(header, 208);
    put32(header, spec.version);
    put32(header, spec.flags);
    put32(header, spec.chunkSize);
    for (int index = 0; index < 16; ++index) {
        header.push_back(static_cast<std::byte>(index));
    }
    put16(header, 1);
    put16(header, 1);
    put32(header, static_cast<std::uint32_t>(spec.images.size()));
    auto putRef = [&](std::uint64_t size,
                      std::uint8_t flags,
                      std::uint64_t offset,
                      std::uint64_t uncompressed) {
        for (std::size_t index = 0; index < 7; ++index) {
            header.push_back(static_cast<std::byte>((size >> (index * 8)) & 0xFF));
        }
        header.push_back(static_cast<std::byte>(flags));
        put64(header, offset);
        put64(header, uncompressed);
    };
    putRef(table.size(), 0x02, lookupAt, table.size());
    putRef(xml.size(), 0x02, xmlAt, xml.size());
    if (spec.bootIndex != 0 && spec.bootIndex <= metaOffsets.size()) {
        // NOTE: boot metadata aliases the selected image's own resource.
        std::uint64_t at = metaOffsets[spec.bootIndex - 1];
        std::uint64_t size = metas[spec.bootIndex - 1].bytes.size();
        putRef(size, 0x02, at, size);
    } else {
        for (int index = 0; index < 24; ++index) {
            header.push_back(std::byte{0});
        }
    }
    put32(header, spec.bootIndex);
    while (header.size() < 208) {
        header.push_back(std::byte{0});
    }

    Bytes out = header;
    out.insert(out.end(), blobs.begin(), blobs.end());
    out.insert(out.end(), table.begin(), table.end());
    out.insert(out.end(), xml.begin(), xml.end());
    return out;
}

}
