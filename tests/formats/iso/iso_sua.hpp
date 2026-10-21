#pragma once

#include "formats/iso/iso_spec.hpp"

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <format>
#include <string>
#include <vector>

namespace bale::iso::test {

inline std::string plainLeaf(const Planned& plan) {
    return plan.file->directory ? detail::upper(plan.leaf)
                                : detail::upper(plan.leaf) + plan.file->version;
}

inline std::string rawName(const Planned& plan) {
    return plan.file->rockRidge ? plan.leaf : plainLeaf(plan);
}

inline std::vector<std::vector<std::byte>> suaBlobs(const Planned& plan, bool dot, bool dotdot) {
    std::vector<std::vector<std::byte>> blobs;
    if (dot) {
        blobs.push_back(
            std::vector<std::byte>{
                std::byte{'S'},
                std::byte{'P'},
                std::byte{7},
                std::byte{1},
                std::byte{0xBE},
                std::byte{0xEF},
                std::byte{0},
            }
        );
    }
    std::uint8_t flags = 0x01 | 0x80;
    bool named = plan.file->rockRidge && !dot && !dotdot;
    bool linked = !plan.file->symlink.empty() && !dot && !dotdot;
    if (named) {
        flags |= 0x08;
    }
    if (linked) {
        flags |= 0x04;
    }
    blobs.push_back(
        std::vector<std::byte>{
            std::byte{'R'},
            std::byte{'R'},
            std::byte{5},
            std::byte{1},
            std::byte{flags},
        }
    );
    if (named) {
        std::vector<std::byte> nm{
            std::byte{'N'},
            std::byte{'M'},
            std::byte{0},
            std::byte{1},
            std::byte{0},
        };
        for (char byte : plan.leaf) {
            nm.push_back(static_cast<std::byte>(byte));
        }
        nm[2] = static_cast<std::byte>(nm.size());
        blobs.push_back(std::move(nm));
    }
    if (linked) {
        std::vector<std::byte> sl{
            std::byte{'S'},
            std::byte{'L'},
            std::byte{0},
            std::byte{1},
            std::byte{0},
        };
        const std::string& target = plan.file->symlink;
        std::size_t at = 0;
        bool first = true;
        while (at <= target.size()) {
            std::size_t end = target.find('/', at);
            if (end == std::string::npos) {
                end = target.size();
            }
            std::string part = target.substr(at, end - at);
            at = end + 1;
            if (part.empty()) {
                if (first) {
                    sl.push_back(std::byte{0x08});
                    sl.push_back(std::byte{0});
                }
                first = false;
                continue;
            }
            first = false;
            if (part == "..") {
                sl.push_back(std::byte{0x04});
                sl.push_back(std::byte{0});
            } else if (part == ".") {
                sl.push_back(std::byte{0x02});
                sl.push_back(std::byte{0});
            } else {
                sl.push_back(std::byte{0});
                sl.push_back(static_cast<std::byte>(part.size()));
                for (char byte : part) {
                    sl.push_back(static_cast<std::byte>(byte));
                }
            }
        }
        sl[2] = static_cast<std::byte>(sl.size());
        blobs.push_back(std::move(sl));
    }
    std::vector<std::byte> px{
        std::byte{'P'},
        std::byte{'X'},
        std::byte{36},
        std::byte{1},
    };
    detail::putBoth32(px, plan.file->mode);
    detail::putBoth32(px, 1);
    detail::putBoth32(px, 1000);
    detail::putBoth32(px, 1000);
    blobs.push_back(std::move(px));
    if (plan.file->longStamp) {
        std::vector<std::byte> tf{
            std::byte{'T'},
            std::byte{'F'},
            std::byte{0},
            std::byte{1},
            std::byte{0x0E},
        };
        std::time_t when = static_cast<std::time_t>(plan.file->mtime);
        std::tm broken{};
#if defined(_WIN32)
        gmtime_s(&broken, &when);
#else
        gmtime_r(&when, &broken);
#endif
        std::string text = std::format(
            "{:04d}{:02d}{:02d}{:02d}{:02d}{:02d}00",
            broken.tm_year + 1900,
            broken.tm_mon + 1,
            broken.tm_mday,
            broken.tm_hour,
            broken.tm_min,
            broken.tm_sec
        );
        for (int index = 0; index < 3; ++index) {
            for (int digit = 0; digit < 16; ++digit) {
                tf.push_back(static_cast<std::byte>(text[static_cast<std::size_t>(digit)]));
            }
            tf.push_back(std::byte{0});
        }
        tf[2] = static_cast<std::byte>(tf.size());
        blobs.push_back(std::move(tf));
    } else {
        std::vector<std::byte> tf{
            std::byte{'T'},
            std::byte{'F'},
            std::byte{26},
            std::byte{1},
            std::byte{0x0E},
        };
        for (int index = 0; index < 3; ++index) {
            for (std::byte byte : detail::shortDate(plan.file->mtime)) {
                tf.push_back(byte);
            }
        }
        blobs.push_back(std::move(tf));
    }
    if (!plan.file->systemExtra.empty() && !dot && !dotdot) {
        std::vector<std::byte> extra;
        for (char byte : plan.file->systemExtra) {
            extra.push_back(static_cast<std::byte>(byte));
        }
        blobs.push_back(std::move(extra));
    }
    return blobs;
}

struct DotSua {
    std::vector<std::vector<std::byte>> dot;
    std::vector<std::vector<std::byte>> dotdot;
};

inline DotSua dotSuaBlobs(bool anyRockRidge) {
    FileSpec dotFile;
    dotFile.mode = 040755;
    dotFile.mtime = 1700000000;
    dotFile.rockRidge = anyRockRidge;
    Planned dotPlan;
    dotPlan.file = &dotFile;
    DotSua sua;
    if (anyRockRidge) {
        sua.dot = suaBlobs(dotPlan, true, false);
        sua.dotdot = suaBlobs(dotPlan, false, true);
    }
    return sua;
}

inline std::vector<std::vector<std::byte>> splitKept(
    std::size_t nameSize,
    std::vector<std::vector<std::byte>> blobs,
    std::vector<std::vector<std::byte>>& overflow
) {
    std::size_t room = 255 - (33 + nameSize + (nameSize % 2 == 0 ? 1 : 0));
    std::size_t used = 0;
    std::size_t keep = blobs.size();
    for (std::size_t index = 0; index < blobs.size(); ++index) {
        if (used + blobs[index].size() + 28 > room) {
            keep = index;
            break;
        }
        used += blobs[index].size();
    }
    if (keep < blobs.size()) {
        auto at = [](auto first, std::size_t n) {
            return first + static_cast<std::ptrdiff_t>(n);
        };
        overflow.assign(at(blobs.begin(), keep), blobs.end());
        blobs.erase(at(blobs.begin(), keep), blobs.end());
    }
    return blobs;
}

}
