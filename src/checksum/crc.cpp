#include "checksum/crc.hpp"

#include "base/endian.hpp"

#include <zlib-ng.h>

#include <array>
#include <atomic>

#if defined(__x86_64__) || defined(_M_X64)
#define BALE_CRC32C_X86 1
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#define BALE_CRC32C_TARGET
#else
#include <cpuid.h>
#include <nmmintrin.h>
#define BALE_CRC32C_TARGET [[gnu::target("sse4.2")]]
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#define BALE_CRC32C_ARM 1
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#define BALE_CRC32C_TARGET
#else
#include <arm_acle.h>
#if defined(__clang__)
#define BALE_CRC32C_TARGET [[gnu::target("crc")]]
#else
#define BALE_CRC32C_TARGET [[gnu::target("+crc")]]
#endif
#endif
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__linux__) || defined(__FreeBSD__)
#include <sys/auxv.h>
#endif
#endif

namespace bale {

namespace {

constexpr std::uint32_t crc32Polynomial = 0xEDB88320;
constexpr std::uint32_t crc32cPolynomial = 0x82F63B78;

using Table = std::array<std::uint32_t, 256>;

template <std::uint32_t Polynomial> constexpr std::array<Table, 8> makeSlicingTables() {
    std::array<Table, 8> result{};
    for (std::uint32_t index = 0; index < 256; ++index) {
        std::uint32_t crc = index;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1) != 0 ? (crc >> 1) ^ Polynomial : crc >> 1;
        }
        result[0][index] = crc;
    }

    for (std::size_t slice = 1; slice < 8; ++slice) {
        for (std::size_t index = 0; index < 256; ++index) {
            std::uint32_t previous = result[slice - 1][index];
            result[slice][index] = (previous >> 8) ^ result[0][previous & 0xFF];
        }
    }
    return result;
}

template <std::uint32_t Polynomial>
constexpr std::array<Table, 8> slicingTables = makeSlicingTables<Polynomial>();

template <std::uint32_t Polynomial>
std::uint32_t slicingBy8(std::uint32_t crc, std::span<const std::byte> data) {
    const auto& tables = slicingTables<Polynomial>;
    std::uint32_t state = ~crc;
    const std::byte* cursor = data.data();
    std::size_t length = data.size();

    while (length >= 8) {
        std::uint32_t low = loadLe<std::uint32_t>(cursor) ^ state;
        std::uint32_t high = loadLe<std::uint32_t>(cursor + 4);
        state = tables[7][low & 0xFF] ^ tables[6][(low >> 8) & 0xFF] ^
            tables[5][(low >> 16) & 0xFF] ^ tables[4][low >> 24] ^ tables[3][high & 0xFF] ^
            tables[2][(high >> 8) & 0xFF] ^ tables[1][(high >> 16) & 0xFF] ^ tables[0][high >> 24];
        cursor += 8;
        length -= 8;
    }

    while (length > 0) {
        state = tables[0][(state ^ std::to_integer<std::uint32_t>(*cursor)) & 0xFF] ^ (state >> 8);
        ++cursor;
        --length;
    }
    return ~state;
}

std::uint32_t zlibNgCrc32(std::uint32_t crc, std::span<const std::byte> data) {
    if (data.empty()) {
        return crc;
    }
    return zng_crc32_z(crc, reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

#ifdef BALE_CRC32C_TARGET

constexpr std::uint32_t multiplyModCrc32c(std::uint32_t a, std::uint32_t b) {
    std::uint32_t product = 0;
    for (std::uint32_t mask = 0x80000000; mask != 0; mask >>= 1) {
        if ((a & mask) != 0) {
            product ^= b;
        }
        b = (b & 1) != 0 ? (b >> 1) ^ crc32cPolynomial : b >> 1;
    }
    return product;
}

constexpr std::array<Table, 4> makeZeroAppendTables(std::size_t bytes) {
    std::uint32_t power = 0x80000000;
    std::uint32_t square = 0x40000000;
    for (std::size_t exponent = bytes * 8; exponent != 0; exponent >>= 1) {
        if ((exponent & 1) != 0) {
            power = multiplyModCrc32c(power, square);
        }
        square = multiplyModCrc32c(square, square);
    }

    std::array<Table, 4> result{};
    for (std::uint32_t lane = 0; lane < 4; ++lane) {
        for (std::uint32_t value = 0; value < 256; ++value) {
            result[lane][value] = multiplyModCrc32c(value << (8 * lane), power);
        }
    }
    return result;
}

template <std::size_t Bytes>
constexpr std::array<Table, 4> zeroAppendTables = makeZeroAppendTables(Bytes);

template <std::size_t Bytes> std::uint32_t appendZeros(std::uint32_t state) {
    const auto& tables = zeroAppendTables<Bytes>;
    return tables[0][state & 0xFF] ^ tables[1][(state >> 8) & 0xFF] ^
        tables[2][(state >> 16) & 0xFF] ^ tables[3][state >> 24];
}

#if defined(BALE_CRC32C_X86)

BALE_CRC32C_TARGET inline std::uint32_t crc32cWord(std::uint32_t state, std::uint64_t word) {
    return static_cast<std::uint32_t>(_mm_crc32_u64(state, word));
}

BALE_CRC32C_TARGET inline std::uint32_t crc32cByte(std::uint32_t state, std::byte byte) {
    return _mm_crc32_u8(state, std::to_integer<std::uint8_t>(byte));
}

bool hasCrc32cInstructions() {
#if defined(_MSC_VER) && !defined(__clang__)
    std::array<int, 4> registers{};
    __cpuid(registers.data(), 1);
    return (registers[2] & (1 << 20)) != 0;
#else
    unsigned eax = 0;
    unsigned ebx = 0;
    unsigned ecx = 0;
    unsigned edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0) {
        return false;
    }
    return (ecx & bit_SSE4_2) != 0;
#endif
}

constexpr std::string_view hardwareKernelName = "sse4.2";

#elif defined(BALE_CRC32C_ARM)

BALE_CRC32C_TARGET inline std::uint32_t crc32cWord(std::uint32_t state, std::uint64_t word) {
    return __crc32cd(state, word);
}

BALE_CRC32C_TARGET inline std::uint32_t crc32cByte(std::uint32_t state, std::byte byte) {
    return __crc32cb(state, std::to_integer<std::uint8_t>(byte));
}

bool hasCrc32cInstructions() {
#if defined(__ARM_FEATURE_CRC32)
    return true;
#elif defined(_WIN32)
    return IsProcessorFeaturePresent(PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE) != 0;
#elif defined(__APPLE__)
    int present = 0;
    std::size_t size = sizeof(present);
    if (sysctlbyname("hw.optional.armv8_crc32", &present, &size, nullptr, 0) != 0) {
        return false;
    }
    return present != 0;
#elif defined(__linux__)
    constexpr unsigned long hwcapCrc32 = 1UL << 7;
    return (getauxval(AT_HWCAP) & hwcapCrc32) != 0;
#elif defined(__FreeBSD__)
    constexpr unsigned long hwcapCrc32 = 1UL << 7;
    unsigned long hwcap = 0;
    if (elf_aux_info(AT_HWCAP, &hwcap, sizeof(hwcap)) != 0) {
        return false;
    }
    return (hwcap & hwcapCrc32) != 0;
#else
    return false;
#endif
}

constexpr std::string_view hardwareKernelName = "armv8-crc";

#endif

template <std::size_t Block>
BALE_CRC32C_TARGET inline std::uint32_t
crc32cThreeWay(std::uint32_t state, const std::byte*& cursor, std::size_t& length) {
    static_assert(Block % 8 == 0);

    while (length >= 3 * Block) {
        std::uint32_t middle = 0;
        std::uint32_t last = 0;
        const std::byte* end = cursor + Block;
        while (cursor != end) {
            state = crc32cWord(state, loadLe<std::uint64_t>(cursor));
            middle = crc32cWord(middle, loadLe<std::uint64_t>(cursor + Block));
            last = crc32cWord(last, loadLe<std::uint64_t>(cursor + 2 * Block));
            cursor += 8;
        }

        state = appendZeros<Block>(appendZeros<Block>(state) ^ middle) ^ last;
        cursor += 2 * Block;
        length -= 3 * Block;
    }
    return state;
}

BALE_CRC32C_TARGET std::uint32_t
crc32cHardware(std::uint32_t crc, std::span<const std::byte> data) {
    std::uint32_t state = ~crc;
    const std::byte* cursor = data.data();
    std::size_t length = data.size();

    while (length > 0 && (reinterpret_cast<std::uintptr_t>(cursor) & 7) != 0) {
        state = crc32cByte(state, *cursor);
        ++cursor;
        --length;
    }

    state = crc32cThreeWay<8192>(state, cursor, length);
    state = crc32cThreeWay<256>(state, cursor, length);

    while (length >= 8) {
        state = crc32cWord(state, loadLe<std::uint64_t>(cursor));
        cursor += 8;
        length -= 8;
    }

    while (length > 0) {
        state = crc32cByte(state, *cursor);
        ++cursor;
        --length;
    }
    return ~state;
}

#endif

CrcFunction selectFunction(CrcAlgorithm algorithm) {
    if (auto accelerated = acceleratedCrcKernel(algorithm)) {
        return accelerated->function;
    }
    return portableCrcKernel(algorithm).function;
}

template <CrcAlgorithm Algorithm>
std::uint32_t resolveAndRun(std::uint32_t crc, std::span<const std::byte> data);

template <CrcAlgorithm Algorithm>
constinit std::atomic<CrcFunction> activeFunction{&resolveAndRun<Algorithm>};

template <CrcAlgorithm Algorithm>
std::uint32_t resolveAndRun(std::uint32_t crc, std::span<const std::byte> data) {
    CrcFunction function = selectFunction(Algorithm);
    activeFunction<Algorithm>.store(function, std::memory_order_relaxed);
    return function(crc, data);
}

}

CrcKernel portableCrcKernel(CrcAlgorithm algorithm) {
    if (algorithm == CrcAlgorithm::Crc32) {
        return {.name = "slicing-by-8", .function = &slicingBy8<crc32Polynomial>};
    }
    return {.name = "slicing-by-8", .function = &slicingBy8<crc32cPolynomial>};
}

std::optional<CrcKernel> acceleratedCrcKernel(CrcAlgorithm algorithm) {
    if (algorithm == CrcAlgorithm::Crc32) {
        return CrcKernel{.name = "zlib-ng", .function = &zlibNgCrc32};
    }

#ifdef BALE_CRC32C_TARGET
    static const bool available = hasCrc32cInstructions();
    if (available) {
        return CrcKernel{.name = hardwareKernelName, .function = &crc32cHardware};
    }
#endif
    return std::nullopt;
}

template <CrcAlgorithm Algorithm> void Crc<Algorithm>::update(std::span<const std::byte> data) {
    value_ = activeFunction<Algorithm>.load(std::memory_order_relaxed)(value_, data);
}

template class Crc<CrcAlgorithm::Crc32>;
template class Crc<CrcAlgorithm::Crc32c>;

}
