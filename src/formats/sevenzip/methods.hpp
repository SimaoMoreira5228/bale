#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace bale::sevenzip {

// NOTE: method IDs below come from the public 7zFormat description and
// Methods.txt (7-Zip 26.04 DOC). The writer only emits single-coder folders
// using Copy, LZMA1, LZMA2, Deflate or BZip2; the remaining IDs exist so the
// reader can name what it refuses.
inline constexpr std::array<std::uint8_t, 1> methodCopy{0x00};
inline constexpr std::array<std::uint8_t, 3> methodLzma1{0x03, 0x01, 0x01};
inline constexpr std::array<std::uint8_t, 1> methodLzma2{0x21};
inline constexpr std::array<std::uint8_t, 3> methodDeflate{0x04, 0x01, 0x08};
inline constexpr std::array<std::uint8_t, 3> methodBzip2{0x04, 0x02, 0x02};
inline constexpr std::array<std::uint8_t, 4> methodAes{0x06, 0xF1, 0x07, 0x01};
inline constexpr std::array<std::uint8_t, 3> methodPpmd{0x03, 0x04, 0x01};
inline constexpr std::array<std::uint8_t, 4> methodBcj{0x03, 0x03, 0x01, 0x03};
inline constexpr std::array<std::uint8_t, 4> methodBcj2{0x03, 0x03, 0x01, 0x1B};
inline constexpr std::array<std::uint8_t, 1> methodDelta{0x03};
inline constexpr std::array<std::uint8_t, 3> methodSwap2{0x02, 0x03, 0x02};
inline constexpr std::array<std::uint8_t, 3> methodSwap4{0x02, 0x03, 0x04};
inline constexpr std::array<std::uint8_t, 4> methodPpc{0x03, 0x03, 0x02, 0x05};
inline constexpr std::array<std::uint8_t, 4> methodIa64{0x03, 0x03, 0x04, 0x01};
inline constexpr std::array<std::uint8_t, 4> methodArm{0x03, 0x03, 0x05, 0x01};
inline constexpr std::array<std::uint8_t, 4> methodArmThumb{0x03, 0x03, 0x07, 0x01};
inline constexpr std::array<std::uint8_t, 4> methodSparc{0x03, 0x03, 0x08, 0x05};
inline constexpr std::array<std::uint8_t, 1> methodArm64{0x0A};
inline constexpr std::array<std::uint8_t, 1> methodRiscv{0x0B};

}
