#pragma once

#include "formats/iso/iso_spec.hpp"
#include "formats/iso/iso_sua.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace bale::iso::test {

inline IsoImage buildIso(const IsoSpec& spec) {

    std::vector<FileSpec> owned = spec.files;
    bool anyRockRidge = false;
    for (const FileSpec& file : owned) {
        if (file.rockRidge) {
            anyRockRidge = true;
        }
    }
    {
        std::map<std::string, bool> haveDir;
        for (const FileSpec& file : owned) {
            if (file.directory) {
                haveDir[file.path] = true;
            }
        }
        std::vector<std::string> implicit;
        for (const FileSpec& file : owned) {
            auto slash = file.path.rfind('/');
            std::string parent = slash == std::string::npos ? "" : file.path.substr(0, slash);
            std::string prefix;
            for (char byte : parent) {
                if (byte == '/') {
                    if (!haveDir.contains(prefix)) {
                        implicit.push_back(prefix);
                        haveDir[prefix] = true;
                    }
                }
                prefix.push_back(byte);
            }
            if (!parent.empty() && !haveDir.contains(parent)) {
                implicit.push_back(parent);
                haveDir[parent] = true;
            }
        }
        for (const std::string& path : implicit) {
            FileSpec dir;
            dir.path = path;
            dir.mode = 040755;
            dir.directory = true;
            dir.rockRidge = anyRockRidge;
            owned.push_back(std::move(dir));
        }
    }
    std::vector<Planned> plans;
    plans.reserve(owned.size());
    for (const FileSpec& file : owned) {
        Planned plan;
        plan.file = &file;
        auto slash = file.path.rfind('/');
        plan.leaf = slash == std::string::npos ? file.path : file.path.substr(slash + 1);
        plan.dataSize = file.symlink.empty() && !file.directory ? file.data.size() : 0;
        plans.push_back(std::move(plan));
    }

    std::map<std::string, PlannedDir> dirs;
    auto ensure = [&](const std::string& path) -> PlannedDir& {
        PlannedDir& dir = dirs[path];
        dir.path = path;
        return dir;
    };
    ensure("");
    for (Planned& plan : plans) {
        auto slash = plan.file->path.rfind('/');
        std::string parent = slash == std::string::npos ? "" : plan.file->path.substr(0, slash);
        std::string prefix;
        for (char byte : parent) {
            if (byte == '/') {
                ensure(prefix);
            }
            prefix.push_back(byte);
        }
        ensure(parent).members.push_back(&plan);
        if (plan.file->directory) {
            ensure(plan.file->path);
        }
    }

    DotSua dots = dotSuaBlobs(anyRockRidge);
    const std::vector<std::vector<std::byte>>& dotKept = dots.dot;
    const std::vector<std::vector<std::byte>>& dotdotKept = dots.dotdot;
    std::size_t dotLength = 34 + detail::suaSizeOf(dotKept);
    std::size_t dotdotLength = 34 + detail::suaSizeOf(dotdotKept);

    for (Planned& plan : plans) {
        std::string name = rawName(plan);
        std::vector<std::vector<std::byte>> blobs;
        if (plan.file->rockRidge) {
            blobs = suaBlobs(plan, false, false);
        } else {
            blobs.push_back(std::vector<std::byte>{});
        }
        plan.keptSua = splitKept(name.size(), std::move(blobs), plan.overflowSua);
        std::size_t suaSize = detail::suaSizeOf(plan.keptSua);
        if (!plan.overflowSua.empty()) {
            suaSize += 28;
        }
        plan.recordLength = 33 + name.size() + (name.size() % 2 == 0 ? 1 : 0) + suaSize;
        if (plan.file->directory || plan.dataSize == 0) {
            plan.pieces.push_back(0);
        } else if (plan.file->extents > 1) {
            std::uint64_t per = plan.dataSize / static_cast<std::uint64_t>(plan.file->extents);
            std::uint64_t left = plan.dataSize;
            for (int index = 0; index < plan.file->extents; ++index) {
                std::uint64_t piece = index + 1 == plan.file->extents ? left : per;
                left -= piece;
                plan.pieces.push_back(piece);
            }
        } else {
            plan.pieces.push_back(plan.dataSize);
        }
    }

    std::uint32_t cursor = 17;
    std::uint32_t bootVd = 0;
    if (spec.boot) {
        bootVd = cursor++;
    }
    std::uint32_t jolietVd = 0;
    if (spec.joliet) {
        jolietVd = cursor++;
    }
    std::uint32_t duplicateVd = 0;
    if (spec.duplicatePvd) {
        duplicateVd = cursor++;
    }
    std::uint32_t terminatorSector = cursor++;

    std::uint32_t udfMark = 0;

    auto dirSize = [&](const PlannedDir& dir) {
        std::size_t total = dotLength + dotdotLength;
        for (const Planned* member : dir.members) {
            total += member->recordLength;
        }
        return ((total + 2047) / 2048) * 2048;
    };

    std::uint32_t lba = terminatorSector + 1;
    if (spec.udfBridge) {
        udfMark = lba;
        lba += 3;
    }
    std::uint32_t pathLba = lba++;
    std::uint32_t pathBeLba = lba++;

    std::vector<PlannedDir*> ordered;
    ordered.reserve(dirs.size());
    for (auto& [path, dir] : dirs) {
        ordered.push_back(&dir);
    }
    for (PlannedDir* dir : ordered) {
        dir->lba = lba;
        dir->size = dirSize(*dir);
        lba += static_cast<std::uint32_t>(dir->size / 2048);
    }

    for (Planned& plan : plans) {
        if (plan.file->directory) {
            continue;
        }
        if (const auto& forced = plan.file->extentLba; forced) {
            plan.dataLba = *forced;
            continue;
        }
        plan.dataLba = lba;
        for (std::uint64_t piece : plan.pieces) {
            lba += static_cast<std::uint32_t>((piece + 2047) / 2048);
        }
    }

    for (Planned& plan : plans) {
        if (plan.overflowSua.empty()) {
            continue;
        }
        plan.overflowLba = lba;
        lba += static_cast<std::uint32_t>((detail::suaSizeOf(plan.overflowSua) + 2047) / 2048);
    }

    std::map<std::string, std::pair<std::uint32_t, std::uint64_t>> jolietDirs;
    if (spec.joliet) {
        for (PlannedDir* dir : ordered) {
            std::uint64_t size = 68;
            for (const Planned* member : dir->members) {
                std::size_t units = member->leaf.size() + member->file->version.size();
                if (member->file->directory) {
                    units = member->leaf.size();
                }
                size += 34 + units * 2;
            }
            size = ((size + 2047) / 2048) * 2048;
            jolietDirs[dir->path] = {lba, size};
            lba += static_cast<std::uint32_t>(size / 2048);
        }
    }

    std::uint32_t catalogLba = 0;
    std::uint32_t bootImageLba = 0;
    if (spec.boot) {
        catalogLba = lba++;
        bootImageLba = lba;
        lba += static_cast<std::uint32_t>((spec.bootData.size() + 2047) / 2048);
    }

    std::vector<std::byte> bytes(static_cast<std::size_t>(lba) * 2048, std::byte{0});
    auto skip = [](auto first, std::size_t n) {
        return first + static_cast<std::ptrdiff_t>(n);
    };
    auto sectorAt = [&](std::uint32_t sector) {
        return std::span(bytes).subspan(static_cast<std::size_t>(sector) * 2048, 2048);
    };

    auto pathTableSize = [&]() {
        std::size_t total = 10;
        for (PlannedDir* dir : ordered) {
            if (dir->path.empty()) {
                continue;
            }
            auto slash = dir->path.rfind('/');
            std::string leaf = slash == std::string::npos ? dir->path : dir->path.substr(slash + 1);
            std::size_t length = detail::upper(leaf).size();
            total += 8 + length + (length % 2 == 0 ? 0 : 1);
        }
        return static_cast<std::uint32_t>(total);
    };

    auto writeVd = [&](std::uint32_t sector,
                       std::uint8_t type,
                       std::uint32_t rootLba,
                       std::uint64_t rootSize,
                       bool jolietSvd) {
        auto area = sectorAt(sector);
        area[0] = static_cast<std::byte>(type);
        area[1] = std::byte{'C'};
        area[2] = std::byte{'D'};
        area[3] = std::byte{'0'};
        area[4] = std::byte{'0'};
        area[5] = std::byte{'1'};
        area[6] = std::byte{1};
        area[7] = std::byte{0};
        for (std::size_t index = 8; index < 40; ++index) {
            area[index] = std::byte{' '};
        }
        const char* system = type == 1 ? "CDROM" : "LINUX";
        for (std::size_t index = 0; system[index] != '\0'; ++index) {
            area[8 + index] = static_cast<std::byte>(system[index]);
        }
        const char* volume = "CDROM";
        for (std::size_t index = 0; volume[index] != '\0'; ++index) {
            area[40 + index] = static_cast<std::byte>(volume[index]);
        }
        std::vector<std::byte> tail;
        detail::putBoth32(tail, lba);
        if (jolietSvd) {
            tail.push_back(std::byte{'%'});
            tail.push_back(std::byte{'/'});
            tail.push_back(std::byte{'E'});
            for (int index = 0; index < 29; ++index) {
                tail.push_back(std::byte{0});
            }
        } else {
            for (int index = 0; index < 32; ++index) {
                tail.push_back(std::byte{0});
            }
        }
        detail::putBoth16(tail, 1);
        detail::putBoth16(tail, 1);
        detail::putBoth16(tail, 2048);
        detail::putBoth32(tail, pathTableSize());
        detail::put32(tail, pathLba);
        detail::put32(tail, 0);
        detail::putBe32(tail, pathBeLba);
        detail::putBe32(tail, 0);
        tail.push_back(std::byte{34});
        tail.push_back(std::byte{0});
        detail::putBoth32(tail, rootLba);
        detail::putBoth32(tail, static_cast<std::uint32_t>(rootSize));
        for (std::byte byte : detail::shortDate(1700000000)) {
            tail.push_back(byte);
        }
        tail.push_back(std::byte{2});
        tail.push_back(std::byte{0});
        tail.push_back(std::byte{0});
        detail::putBoth16(tail, 1);
        tail.push_back(std::byte{1});
        tail.push_back(std::byte{0});
        std::copy(tail.begin(), tail.end(), area.begin() + 80);
    };

    writeVd(16, 1, ordered[0]->lba, ordered[0]->size, false);
    if (spec.boot) {
        auto area = sectorAt(bootVd);
        area[0] = std::byte{0};
        area[1] = std::byte{'C'};
        area[2] = std::byte{'D'};
        area[3] = std::byte{'0'};
        area[4] = std::byte{'0'};
        area[5] = std::byte{'1'};
        area[6] = std::byte{1};
        const char* id = "EL TORITO SPECIFICATION";
        for (std::size_t index = 0; id[index] != '\0'; ++index) {
            area[7 + index] = static_cast<std::byte>(id[index]);
        }
        std::vector<std::byte> field;
        detail::put32(field, catalogLba);
        std::copy(field.begin(), field.end(), area.begin() + 71);
    }
    if (spec.joliet) {
        writeVd(jolietVd, 2, jolietDirs[""].first, jolietDirs[""].second, true);
    }
    if (spec.duplicatePvd) {
        writeVd(duplicateVd, 1, ordered[0]->lba, ordered[0]->size, false);
    }

    IsoImage image;
    if (!spec.noTerminator) {
        auto area = sectorAt(terminatorSector);
        area[0] = std::byte{255};
        area[1] = std::byte{'C'};
        area[2] = std::byte{'D'};
        area[3] = std::byte{'0'};
        area[4] = std::byte{'0'};
        area[5] = std::byte{'1'};
        area[6] = std::byte{1};
    }
    image.terminatorByte = static_cast<std::size_t>(terminatorSector) * 2048;

    if (spec.udfBridge) {
        const char* markers[3] = {"BEA01", "NSR02", "TEA01"};
        for (int mark = 0; mark < 3; ++mark) {
            auto area = sectorAt(udfMark + static_cast<std::uint32_t>(mark));
            area[0] = std::byte{0};
            for (std::size_t index = 0; markers[mark][index] != '\0'; ++index) {
                area[1 + index] = static_cast<std::byte>(markers[mark][index]);
            }
            area[6] = std::byte{1};
        }
    }

    {
        auto writeOne = [&](std::uint32_t at, bool bigEndian) {
            auto area = sectorAt(at);
            std::size_t pos = 0;
            auto emit = [&](std::string_view name, std::uint32_t extent, std::uint16_t parent) {
                std::vector<std::byte> record;
                record.push_back(static_cast<std::byte>(name.size()));
                record.push_back(std::byte{0});
                if (bigEndian) {
                    detail::putBe32(record, extent);
                    detail::put16Be(record, parent);
                } else {
                    detail::put32(record, extent);
                    detail::put16(record, parent);
                }
                for (char byte : name) {
                    record.push_back(static_cast<std::byte>(byte));
                }
                if (name.size() % 2 == 0) {
                    record.push_back(std::byte{0});
                }
                std::copy(record.begin(), record.end(), skip(area.begin(), pos));
                pos += record.size();
            };
            std::string rootName("\0", 1);
            emit(rootName, ordered[0]->lba, 1);
            for (PlannedDir* dir : ordered) {
                if (dir->path.empty()) {
                    continue;
                }
                auto slash = dir->path.rfind('/');
                std::string leaf =
                    slash == std::string::npos ? dir->path : dir->path.substr(slash + 1);
                std::string parent = slash == std::string::npos ? "" : dir->path.substr(0, slash);
                std::uint16_t parentIndex = 1;
                std::uint16_t scan = 2;
                for (PlannedDir* other : ordered) {
                    if (other->path.empty()) {
                        continue;
                    }
                    if (other->path == parent) {
                        parentIndex = scan;
                    }
                    ++scan;
                }
                emit(detail::upper(leaf), dir->lba, parentIndex);
            }
        };
        writeOne(pathLba, false);
        writeOne(pathBeLba, true);
    }

    auto makeRecord = [&](std::uint32_t extent,
                          std::uint64_t size,
                          std::uint8_t flags,
                          std::int64_t mtime,
                          std::string_view name,
                          const std::vector<std::vector<std::byte>>& blobs,
                          std::uint32_t overflow,
                          std::uint64_t overflowSize) {
        std::vector<std::byte> record;
        record.push_back(std::byte{0});
        record.push_back(std::byte{0});
        detail::putBoth32(record, extent);
        detail::putBoth32(record, static_cast<std::uint32_t>(size));
        for (std::byte byte : detail::shortDate(mtime)) {
            record.push_back(byte);
        }
        record.push_back(std::byte{flags});
        record.push_back(std::byte{0});
        record.push_back(std::byte{0});
        detail::putBoth16(record, 1);
        record.push_back(static_cast<std::byte>(name.size()));
        for (char byte : name) {
            record.push_back(static_cast<std::byte>(byte));
        }
        if (name.size() % 2 == 0) {
            record.push_back(std::byte{0});
        }
        for (const auto& blob : blobs) {
            record.insert(record.end(), blob.begin(), blob.end());
        }
        std::vector<std::byte> tail;
        if (overflow != 0) {
            tail = std::vector<std::byte>{
                std::byte{'C'},
                std::byte{'E'},
                std::byte{28},
                std::byte{1},
            };
            detail::putBoth32(tail, overflow);
            detail::putBoth32(tail, 0);
            detail::putBoth32(tail, static_cast<std::uint32_t>(overflowSize));
        }
        return std::make_pair(record, tail);
    };

    for (Planned& plan : plans) {
        if (plan.overflowSua.empty()) {
            continue;
        }
        auto area = sectorAt(plan.overflowLba);
        std::size_t pos = 0;
        for (const auto& blob : plan.overflowSua) {
            std::copy(blob.begin(), blob.end(), skip(area.begin(), pos));
            pos += blob.size();
        }
    }

    for (PlannedDir* dir : ordered) {
        auto area = sectorAt(dir->lba);
        std::size_t pos = 0;
        PlannedDir* parent = &dirs[""];
        if (!dir->path.empty()) {
            auto slash = dir->path.rfind('/');
            std::string up = slash == std::string::npos ? "" : dir->path.substr(0, slash);
            parent = &dirs[up];
        }
        auto emitRecord = [&](std::vector<std::byte> record, const std::vector<std::byte>& tail) {
            record[0] = static_cast<std::byte>(record.size() + tail.size());
            std::copy(record.begin(), record.end(), skip(area.begin(), pos));
            pos += record.size();
            std::copy(tail.begin(), tail.end(), skip(area.begin(), pos));
            pos += tail.size();
        };
        {
            std::string dotName("\0", 1);
            auto [record, tail] =
                makeRecord(dir->lba, dir->size, 0x02, 1700000000, dotName, dotKept, 0, 0);
            emitRecord(std::move(record), tail);
        }
        {
            std::string dotdot("\x01", 1);
            auto [record, tail] =
                makeRecord(parent->lba, parent->size, 0x02, 1700000000, dotdot, dotdotKept, 0, 0);
            emitRecord(std::move(record), tail);
        }
        for (Planned* member : dir->members) {
            std::string name = rawName(*member);
            std::uint8_t flags = member->file->directory ? 0x02 : 0x00;
            if (member->file->directory) {
                PlannedDir& sub = dirs[member->file->path];
                auto [record, tail] = makeRecord(
                    sub.lba,
                    sub.size,
                    flags,
                    member->file->mtime,
                    name,
                    member->keptSua,
                    member->overflowLba,
                    detail::suaSizeOf(member->overflowSua)
                );
                image.records[member->file->path] = static_cast<std::size_t>(dir->lba) * 2048 + pos;
                emitRecord(std::move(record), tail);
            } else if (member->pieces.size() > 1) {
                std::uint32_t partLba = member->dataLba;
                for (std::size_t index = 0; index < member->pieces.size(); ++index) {
                    std::uint8_t partFlags = flags;
                    if (index + 1 < member->pieces.size()) {
                        partFlags |= 0x80;
                    }
                    auto [record, tail] = makeRecord(
                        partLba,
                        member->pieces[index],
                        partFlags,
                        member->file->mtime,
                        name,
                        index == 0 ? member->keptSua : std::vector<std::vector<std::byte>>{},
                        index == 0 ? member->overflowLba : 0,
                        index == 0 ? detail::suaSizeOf(member->overflowSua) : 0
                    );
                    if (index == 0) {
                        image.records[member->file->path] =
                            static_cast<std::size_t>(dir->lba) * 2048 + pos;
                    }
                    emitRecord(std::move(record), tail);
                    partLba += static_cast<std::uint32_t>((member->pieces[index] + 2047) / 2048);
                }
            } else {
                auto [record, tail] = makeRecord(
                    member->dataLba,
                    member->dataSize,
                    flags,
                    member->file->mtime,
                    name,
                    member->keptSua,
                    member->overflowLba,
                    detail::suaSizeOf(member->overflowSua)
                );
                image.records[member->file->path] = static_cast<std::size_t>(dir->lba) * 2048 + pos;
                emitRecord(std::move(record), tail);
            }
        }
    }

    for (Planned& plan : plans) {
        if (plan.file->directory || plan.file->extentLba || !plan.file->symlink.empty()) {
            continue;
        }
        std::size_t at = static_cast<std::size_t>(plan.dataLba) * 2048;
        std::string_view left(plan.file->data.data(), plan.file->data.size());
        for (std::uint64_t piece : plan.pieces) {
            std::size_t count = static_cast<std::size_t>(piece);
            for (std::size_t index = 0; index < count; ++index) {
                bytes[at + index] = static_cast<std::byte>(left[index]);
            }
            left.remove_prefix(count);
            at += ((count + 2047) / 2048) * 2048;
        }
    }

    if (spec.joliet) {
        for (PlannedDir* dir : ordered) {
            auto [treeLba, treeSize] = jolietDirs[dir->path];
            auto area = sectorAt(treeLba);
            std::size_t pos = 0;
            if (dir->path.empty()) {
                image.jolietRootByte = static_cast<std::size_t>(treeLba) * 2048;
            }
            PlannedDir* parent = &dirs[""];
            if (!dir->path.empty()) {
                auto slash = dir->path.rfind('/');
                std::string up = slash == std::string::npos ? "" : dir->path.substr(0, slash);
                parent = &dirs[up];
            }
            auto [parentLba, parentSize] = jolietDirs[parent->path];
            auto emitJoliet = [&](std::uint32_t extent,
                                  std::uint64_t size,
                                  std::uint8_t flags,
                                  std::string_view name,
                                  std::string_view suffix) {
                std::vector<std::byte> record;
                record.push_back(std::byte{0});
                record.push_back(std::byte{0});
                detail::putBoth32(record, extent);
                detail::putBoth32(record, static_cast<std::uint32_t>(size));
                for (std::byte byte : detail::shortDate(1700000000)) {
                    record.push_back(byte);
                }
                record.push_back(std::byte{flags});
                record.push_back(std::byte{0});
                record.push_back(std::byte{0});
                detail::putBoth16(record, 1);
                std::string full(name);
                full.append(suffix);
                std::vector<std::byte> encoded;
                if (full.size() == 1 && (full[0] == '\0' || full[0] == '\x01')) {
                    encoded.push_back(static_cast<std::byte>(full[0]));
                } else {
                    for (char byte : full) {
                        encoded.push_back(std::byte{0});
                        encoded.push_back(static_cast<std::byte>(byte));
                    }
                }
                record.push_back(static_cast<std::byte>(encoded.size()));
                record.insert(record.end(), encoded.begin(), encoded.end());
                if (encoded.size() % 2 == 0) {
                    record.push_back(std::byte{0});
                }
                record[0] = static_cast<std::byte>(record.size());
                std::copy(record.begin(), record.end(), skip(area.begin(), pos));
                pos += record.size();
            };
            emitJoliet(treeLba, treeSize, 0x02, std::string("\0", 1), "");
            emitJoliet(parentLba, parentSize, 0x02, std::string("\x01", 1), "");
            for (Planned* member : dir->members) {
                if (member->file->directory) {
                    PlannedDir& sub = dirs[member->file->path];
                    auto [subLba, subSize] = jolietDirs[sub.path];
                    emitJoliet(subLba, subSize, 0x02, member->leaf, "");
                } else {
                    emitJoliet(
                        member->dataLba,
                        member->dataSize,
                        0x00,
                        member->leaf,
                        member->file->version
                    );
                }
            }
        }
    }

    if (spec.boot) {
        auto area = sectorAt(catalogLba);
        image.catalogByte = static_cast<std::size_t>(catalogLba) * 2048;
        area[0] = std::byte{1};
        area[1] = std::byte{0};
        std::uint32_t sum = 0x0001;
        for (std::size_t index = 2; index < 28; index += 2) {
            sum += static_cast<std::uint32_t>(static_cast<unsigned char>(area[index])) |
                (static_cast<std::uint32_t>(static_cast<unsigned char>(area[index + 1])) << 8);
        }
        std::uint32_t check = (0x10000 - ((sum + 0xAA55) & 0xFFFF)) & 0xFFFF;
        area[28] = static_cast<std::byte>(check & 0xFF);
        area[29] = static_cast<std::byte>((check >> 8) & 0xFF);
        area[30] = std::byte{0x55};
        area[31] = std::byte{0xAA};
        area[32] = std::byte{0x88};
        area[33] = std::byte{0};
        area[34] = std::byte{0};
        area[35] = std::byte{0};
        area[36] = std::byte{0};
        area[37] = std::byte{0};
        auto sectors = static_cast<std::uint16_t>((spec.bootData.size() + 511) / 512);
        area[38] = static_cast<std::byte>(sectors & 0xFF);
        area[39] = static_cast<std::byte>((sectors >> 8) & 0xFF);
        std::vector<std::byte> field;
        detail::put32(field, bootImageLba);
        std::copy(field.begin(), field.end(), area.begin() + 40);
        image.bootImageByte = static_cast<std::size_t>(bootImageLba) * 2048;
        for (std::size_t index = 0; index < spec.bootData.size(); ++index) {
            bytes[image.bootImageByte + index] = static_cast<std::byte>(spec.bootData[index]);
        }
    }

    image.bytes = std::move(bytes);
    return image;
}

}
