#include "cli/terminal_text.hpp"
#include "fuzz/memory_file.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view raw(reinterpret_cast<const char*>(data), size);
    std::string buffer;
    auto escaped = bale::cli::escapeForTerminal(raw, buffer);

    for (std::size_t index = 0; index < escaped.size(); ++index) {
        auto byte = static_cast<unsigned char>(escaped[index]);
        if (byte < 0x20 || byte == 0x7F) {
            __builtin_trap();
        }
        bool c1 = byte == 0xC2 && index + 1 < escaped.size() &&
            static_cast<unsigned char>(escaped[index + 1]) >= 0x80 &&
            static_cast<unsigned char>(escaped[index + 1]) <= 0x9F;
        if (c1) {
            __builtin_trap();
        }
    }
    return 0;
}
