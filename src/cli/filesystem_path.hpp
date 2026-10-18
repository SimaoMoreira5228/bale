#pragma once

#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>

namespace bale::cli {

inline std::filesystem::path pathFromUtf8(std::string_view value) {
#ifdef _WIN32
    std::u8string encoded(value.size(), u8'\0');
    std::memcpy(encoded.data(), value.data(), value.size());
    return std::filesystem::path(encoded);
#else
    return std::filesystem::path(value);
#endif
}

inline std::string pathToUtf8(const std::filesystem::path& path) {
#ifdef _WIN32
    std::u8string encoded = path.u8string();
    std::string value(encoded.size(), '\0');
    std::memcpy(value.data(), encoded.data(), encoded.size());
    return value;
#else
    return path.native();
#endif
}

}
