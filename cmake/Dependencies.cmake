option(
    BALE_USE_SYSTEM_CODECS
    "Link system zlib-ng, zstd, LZ4 and BLAKE3 instead of building pinned sources"
    OFF
)

add_library(bale_zlib_ng INTERFACE)
add_library(bale_zstd INTERFACE)
add_library(bale_lz4 INTERFACE)
add_library(bale_blake3 INTERFACE)
add_library(bale_expected INTERFACE)
add_library(bale_lzma INTERFACE)
add_library(bale_bz2 INTERFACE)
add_library(bale_brotli INTERFACE)
add_library(bale_sodium INTERFACE)

if(BALE_USE_SYSTEM_CODECS)
    find_package(zlib-ng CONFIG QUIET)
    find_package(zstd CONFIG QUIET)
    find_package(PkgConfig QUIET)

    if(TARGET zlib-ng::zlib)
        target_link_libraries(bale_zlib_ng INTERFACE zlib-ng::zlib)
    elseif(PkgConfig_FOUND)
        pkg_check_modules(BALE_SYSTEM_ZLIB_NG REQUIRED IMPORTED_TARGET zlib-ng)
        target_link_libraries(bale_zlib_ng INTERFACE PkgConfig::BALE_SYSTEM_ZLIB_NG)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: zlib-ng (native API) not found")
    endif()

    if(TARGET zstd::libzstd)
        target_link_libraries(bale_zstd INTERFACE zstd::libzstd)
    elseif(TARGET zstd::libzstd_shared)
        target_link_libraries(bale_zstd INTERFACE zstd::libzstd_shared)
    elseif(TARGET zstd::libzstd_static)
        target_link_libraries(bale_zstd INTERFACE zstd::libzstd_static)
    elseif(PkgConfig_FOUND)
        pkg_check_modules(BALE_SYSTEM_ZSTD REQUIRED IMPORTED_TARGET libzstd>=1.5.0)
        target_link_libraries(bale_zstd INTERFACE PkgConfig::BALE_SYSTEM_ZSTD)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: zstd not found")
    endif()

    find_package(lz4 1.9 CONFIG QUIET)
    if(TARGET LZ4::lz4)
        target_link_libraries(bale_lz4 INTERFACE LZ4::lz4)
    elseif(TARGET lz4::lz4)
        target_link_libraries(bale_lz4 INTERFACE lz4::lz4)
    elseif(TARGET LZ4::lz4_shared)
        target_link_libraries(bale_lz4 INTERFACE LZ4::lz4_shared)
    elseif(TARGET LZ4::lz4_static)
        target_link_libraries(bale_lz4 INTERFACE LZ4::lz4_static)
    elseif(PkgConfig_FOUND)
        pkg_check_modules(BALE_SYSTEM_LZ4 REQUIRED IMPORTED_TARGET liblz4>=1.9.0)
        target_link_libraries(bale_lz4 INTERFACE PkgConfig::BALE_SYSTEM_LZ4)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: LZ4 not found")
    endif()

    find_package(blake3 1.5 CONFIG QUIET)
    if(TARGET BLAKE3::blake3)
        target_link_libraries(bale_blake3 INTERFACE BLAKE3::blake3)
    elseif(PkgConfig_FOUND)
        pkg_check_modules(BALE_SYSTEM_BLAKE3 REQUIRED IMPORTED_TARGET libblake3>=1.5)
        target_link_libraries(bale_blake3 INTERFACE PkgConfig::BALE_SYSTEM_BLAKE3)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: BLAKE3 not found")
    endif()

    find_package(tl-expected 1.2 CONFIG QUIET)
    if(TARGET tl::expected)
        target_link_libraries(bale_expected INTERFACE tl::expected)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: tl-expected not found")
    endif()

    find_package(LibLZMA QUIET)
    if(TARGET LibLZMA::LibLZMA)
        target_link_libraries(bale_lzma INTERFACE LibLZMA::LibLZMA)
    elseif(PkgConfig_FOUND)
        pkg_check_modules(BALE_SYSTEM_LZMA REQUIRED IMPORTED_TARGET liblzma>=5.4.0)
        target_link_libraries(bale_lzma INTERFACE PkgConfig::BALE_SYSTEM_LZMA)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: liblzma not found")
    endif()

    find_package(BZip2 QUIET)
    if(TARGET BZip2::BZip2)
        target_link_libraries(bale_bz2 INTERFACE BZip2::BZip2)
    elseif(PkgConfig_FOUND)
        pkg_check_modules(BALE_SYSTEM_BZ2 REQUIRED IMPORTED_TARGET bzip2)
        target_link_libraries(bale_bz2 INTERFACE PkgConfig::BALE_SYSTEM_BZ2)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: bzip2 not found")
    endif()

    if(PkgConfig_FOUND)
        pkg_check_modules(
            BALE_SYSTEM_BROTLI REQUIRED IMPORTED_TARGET libbrotlienc>=1.0.0 libbrotlidec>=1.0.0
        )
        target_link_libraries(bale_brotli INTERFACE PkgConfig::BALE_SYSTEM_BROTLI)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: brotli not found")
    endif()

    if(PkgConfig_FOUND)
        pkg_check_modules(BALE_SYSTEM_SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)
        target_link_libraries(bale_sodium INTERFACE PkgConfig::BALE_SYSTEM_SODIUM)
    else()
        message(FATAL_ERROR "BALE_USE_SYSTEM_CODECS: libsodium not found")
    endif()
    return()
endif()

enable_language(C)
include(FetchContent)

FetchContent_Declare(zlib_ng
    URL https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.3.3.tar.gz
    URL_HASH SHA256=f9c65aa9c852eb8255b636fd9f07ce1c406f061ec19a2e7d508b318ca0c907d1
    SYSTEM
)
FetchContent_Declare(zstd
    URL https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
    URL_HASH SHA256=eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3
    SOURCE_SUBDIR build/cmake
    SYSTEM
)
FetchContent_Declare(lz4
    URL https://github.com/lz4/lz4/releases/download/v1.10.0/lz4-1.10.0.tar.gz
    URL_HASH SHA256=537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b
    SOURCE_SUBDIR build/cmake
    SYSTEM
)
FetchContent_Declare(blake3
    URL https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/1.8.7.tar.gz
    URL_HASH SHA256=c6782a28842b1c0478524ac06a4f2ede784038ee298d6e2162c0b089c4306a3c
    SOURCE_SUBDIR c
    SYSTEM
)
# NOTE: tl::expected is CC0 public domain (see the header), a single header with no
# sources to build. The std::expected in libstdc++ is unavailable under Clang, which
# does not advertise a completed concepts implementation that libstdc++ requires, so
# the portable standard-library type cannot be relied on. This pins the same API.
FetchContent_Declare(tl_expected
    URL https://github.com/TartanLlama/expected/archive/refs/tags/v1.3.1.tar.gz
    URL_HASH SHA256=9a04f4f472fbb5c30bf60402f1ca626c4a76987f867978d0b8a35d7ab3fb8fe7
    SYSTEM
)
FetchContent_Declare(xz
    URL https://github.com/tukaani-project/xz/releases/download/v5.8.4/xz-5.8.4.tar.gz
    URL_HASH SHA256=0014c7886930454fe8bd4228665b51af55eeae560ea135c9c4cd33f55b2591d9
    SYSTEM
)
# NOTE: brotli 1.2.0 (MIT, https://github.com/google/brotli/releases/tag/v1.2.0).
# Upstream ships a first-party CMake build, so bale pins the release tarball by hash
# and builds only the C libraries statically. The Java/Python bindings, the `brotli`
# tool and the round-trip tests stay out via BROTLI_BUILD_TOOLS=OFF below.
FetchContent_Declare(brotli
    URL https://github.com/google/brotli/archive/refs/tags/v1.2.0.tar.gz
    URL_HASH SHA256=816c96e8e8f193b40151dad7e8ff37b1221d019dbcb9c35cd3fadbfe6477dfec
    SYSTEM
)

block(SCOPE_FOR VARIABLES)
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_TESTING OFF)

    # NOTE: both projects force a cached Release build type when none is set, which would silently
    # change the build type of bale itself; a scoped value keeps them optimized and the cache clean.
    get_property(multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
    if(NOT multi_config AND NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release)
    endif()

    set(ZLIB_COMPAT OFF)
    set(ZLIB_ALIASES OFF)
    set(WITH_GZFILEOP OFF)
    set(WITH_GTEST OFF)
    set(WITH_FUZZERS OFF)
    set(WITH_BENCHMARKS OFF)
    set(WITH_NATIVE_INSTRUCTIONS OFF)
    set(WITH_RUNTIME_CPU_DETECTION ON)
    set(SKIP_INSTALL_ALL ON)

    set(ZSTD_BUILD_STATIC ON)
    set(ZSTD_BUILD_SHARED OFF)
    set(ZSTD_BUILD_PROGRAMS OFF)
    set(ZSTD_BUILD_TESTS OFF)
    set(ZSTD_BUILD_CONTRIB OFF)
    set(ZSTD_BUILD_DICTBUILDER OFF)
    set(ZSTD_LEGACY_SUPPORT OFF)
    set(ZSTD_MULTITHREAD_SUPPORT OFF)

    # NOTE: LZ4 1.10 still declares cmake_minimum_required(3.5), which CMake 3.31+ flags as
    # deprecated; the other projects already require 3.10 or newer, so only LZ4 is affected.
    set(CMAKE_POLICY_VERSION_MINIMUM 3.10)
    set(BUILD_STATIC_LIBS ON)
    set(LZ4_BUILD_CLI OFF)
    set(LZ4_BUNDLED_MODE ON)

    set(BLAKE3_USE_TBB OFF)
    set(BLAKE3_FETCH_TBB OFF)
    set(BLAKE3_EXAMPLES OFF)
    set(BLAKE3_TESTING OFF)

    # NOTE: header-only; nothing to build. Tests and packaging stay out.
    set(EXPECTED_BUILD_TESTS OFF)
    set(EXPECTED_BUILD_PACKAGE OFF)

    # NOTE: only the decoder library is needed; the command line tools, scripts,
    # translated messages and API docs stay out of the build.
    set(XZ_TOOL_XZ OFF)
    set(XZ_TOOL_XZDEC OFF)
    set(XZ_TOOL_LZMADEC OFF)
    set(XZ_TOOL_LZMAINFO OFF)
    set(XZ_TOOL_SCRIPTS OFF)
    set(XZ_DOC OFF)
    set(XZ_NLS OFF)
    # NOTE: the sandbox only confines the xz tools above, which bale never builds, so this
    # changes nothing in the library. xz's configure hard-errors when CFLAGS holds
    # -fsanitize, which would needlessly break sanitizer builds (./dev sanitize).
    set(XZ_SANDBOX no)

    # NOTE: only the brotli libraries are needed; the command line tool, the Java and
    # Python bindings and the test data stay out of the build. BROTLI_DISABLE_TESTS
    # gates brotli's own CTest round trips separately from BUILD_TESTING.
    set(BROTLI_BUILD_TOOLS OFF)
    set(BROTLI_DISABLE_TESTS ON)

    FetchContent_MakeAvailable(zlib_ng zstd lz4 blake3 xz brotli tl_expected)
endblock()

# NOTE: bzip2 ships no CMake build, so bale verifies the tarball by hash and compiles
# the library sources directly. Only the bzip2 and bzip2recover tools are left out.
set(BALE_BZIP2_URL https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz)
set(BALE_BZIP2_SHA256 ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269)
set(BALE_BZIP2_ARCHIVE ${CMAKE_BINARY_DIR}/bzip2-1.0.8.tar.gz)
set(BALE_BZIP2_SOURCE_DIR ${CMAKE_BINARY_DIR}/bzip2-1.0.8)
if(NOT EXISTS ${BALE_BZIP2_SOURCE_DIR}/bzlib.h)
    file(DOWNLOAD ${BALE_BZIP2_URL} ${BALE_BZIP2_ARCHIVE} EXPECTED_HASH SHA256=${BALE_BZIP2_SHA256})
    file(ARCHIVE_EXTRACT INPUT ${BALE_BZIP2_ARCHIVE} DESTINATION ${CMAKE_BINARY_DIR})
endif()
add_library(bale_bz2_static STATIC
    ${BALE_BZIP2_SOURCE_DIR}/blocksort.c
    ${BALE_BZIP2_SOURCE_DIR}/bzlib.c
    ${BALE_BZIP2_SOURCE_DIR}/compress.c
    ${BALE_BZIP2_SOURCE_DIR}/crctable.c
    ${BALE_BZIP2_SOURCE_DIR}/decompress.c
    ${BALE_BZIP2_SOURCE_DIR}/huffman.c
    ${BALE_BZIP2_SOURCE_DIR}/randtable.c
)
target_include_directories(bale_bz2_static SYSTEM PUBLIC ${BALE_BZIP2_SOURCE_DIR})
target_link_libraries(bale_bz2 INTERFACE bale_bz2_static)

target_link_libraries(bale_zlib_ng INTERFACE zlib-ng::zlib)
target_link_libraries(bale_zstd INTERFACE libzstd_static)
target_link_libraries(bale_lz4 INTERFACE lz4_static)
target_link_libraries(bale_blake3 INTERFACE BLAKE3::blake3)
target_link_libraries(bale_expected INTERFACE tl::expected)
# NOTE: liblzma's CMake target does not expose its API headers, so bale adds them
# explicitly instead of picking up whatever lzma.h the system happens to provide.
FetchContent_GetProperties(xz SOURCE_DIR XZ_SOURCE_DIR)
target_include_directories(bale_lzma SYSTEM INTERFACE ${XZ_SOURCE_DIR}/src/liblzma/api)
target_link_libraries(bale_lzma INTERFACE liblzma)

# NOTE: with BUILD_SHARED_LIBS off the brotli targets above are static archives;
# decoding never enables the large-window extension, so the ring buffer stays
# within the RFC 7932 window of at most 2^24 bytes.
target_link_libraries(bale_brotli INTERFACE brotlienc brotlidec brotlicommon)

# NOTE: libsodium 1.0.20-stable (ISC, https://download.libsodium.org/libsodium/releases).
# Upstream ships autotools configure plus Visual Studio projects and no first-party
# CMake build, and bale does not pull a third-party CMake shim in as a new dependency
# to drive it. The static library below compiles libsodium's own portable C sources
# directly, limited to what the encrypted profile needs: XChaCha20-Poly1305 AEAD,
# Argon2id password hashing, X25519 sealed boxes and Ed25519 (reserved, no signing
# yet). Everything else the tarball carries (AES-GCM, AEGIS, scrypt, secretstream,
# short hashes, KDF/KX helpers, xchacha secretbox/box, salsa2012/208 streams, the
# SIMD back ends for other ciphers) is left out. sodium_init still links because the
# two AEGIS selector stubs in cmake/sodium_aegis_stubs.c satisfy its references;
# those stubs are bale code, not patched upstream sources.
set(BALE_SODIUM_URL https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable.tar.gz)
set(BALE_SODIUM_SHA256 b6b1d2a8802cd8bfa611638c0e9ce31d14ef324e16062c39a76854091cba6d7f)
set(BALE_SODIUM_ARCHIVE ${CMAKE_BINARY_DIR}/libsodium-1.0.20-stable.tar.gz)
set(BALE_SODIUM_SOURCE_DIR ${CMAKE_BINARY_DIR}/libsodium-stable/src/libsodium)
if(NOT EXISTS ${BALE_SODIUM_SOURCE_DIR}/include/sodium.h)
    file(DOWNLOAD ${BALE_SODIUM_URL} ${BALE_SODIUM_ARCHIVE} EXPECTED_HASH SHA256=${BALE_SODIUM_SHA256})
    file(ARCHIVE_EXTRACT INPUT ${BALE_SODIUM_ARCHIVE} DESTINATION ${CMAKE_BINARY_DIR})
endif()
set(BALE_SODIUM_FILES
    sodium/core.c
    sodium/runtime.c
    sodium/utils.c
    sodium/codecs.c
    sodium/version.c
    randombytes/randombytes.c
    randombytes/sysrandom/randombytes_sysrandom.c
    crypto_verify/verify.c
    crypto_aead/xchacha20poly1305/aead_xchacha20poly1305.c
    crypto_aead/chacha20poly1305/aead_chacha20poly1305.c
    crypto_stream/chacha20/stream_chacha20.c
    crypto_stream/chacha20/ref/chacha20_ref.c
    crypto_core/hchacha20/core_hchacha20.c
    crypto_onetimeauth/crypto_onetimeauth.c
    crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
    crypto_onetimeauth/poly1305/donna/poly1305_donna.c
    crypto_stream/crypto_stream.c
    crypto_stream/salsa20/stream_salsa20.c
    crypto_stream/salsa20/ref/salsa20_ref.c
    crypto_stream/xsalsa20/stream_xsalsa20.c
    crypto_core/salsa/ref/core_salsa_ref.c
    crypto_core/hsalsa20/core_hsalsa20.c
    crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c
    crypto_secretbox/crypto_secretbox.c
    crypto_secretbox/crypto_secretbox_easy.c
    crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c
    crypto_box/crypto_box.c
    crypto_box/crypto_box_easy.c
    crypto_box/crypto_box_seal.c
    crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c
    crypto_scalarmult/crypto_scalarmult.c
    crypto_scalarmult/curve25519/scalarmult_curve25519.c
    crypto_scalarmult/curve25519/ref10/x25519_ref10.c
    crypto_core/ed25519/ref10/ed25519_ref10.c
    crypto_generichash/crypto_generichash.c
    crypto_generichash/blake2b/ref/blake2b-ref.c
    crypto_generichash/blake2b/ref/blake2b-compress-ref.c
    crypto_generichash/blake2b/ref/generichash_blake2b.c
    crypto_hash/crypto_hash.c
    crypto_hash/sha256/hash_sha256.c
    crypto_hash/sha256/cp/hash_sha256_cp.c
    crypto_hash/sha512/hash_sha512.c
    crypto_hash/sha512/cp/hash_sha512_cp.c
    crypto_pwhash/crypto_pwhash.c
    crypto_pwhash/argon2/argon2.c
    crypto_pwhash/argon2/argon2-core.c
    crypto_pwhash/argon2/argon2-encoding.c
    crypto_pwhash/argon2/argon2-fill-block-ref.c
    crypto_pwhash/argon2/blake2b-long.c
    crypto_pwhash/argon2/pwhash_argon2i.c
    crypto_pwhash/argon2/pwhash_argon2id.c
    crypto_sign/crypto_sign.c
    crypto_sign/ed25519/sign_ed25519.c
    crypto_sign/ed25519/ref10/keypair.c
    crypto_sign/ed25519/ref10/open.c
    crypto_sign/ed25519/ref10/sign.c
)
list(TRANSFORM BALE_SODIUM_FILES PREPEND "${BALE_SODIUM_SOURCE_DIR}/")
add_library(bale_sodium_static STATIC
    ${BALE_SODIUM_FILES}
    ${CMAKE_CURRENT_LIST_DIR}/sodium_aegis_stubs.c
)
# NOTE: CONFIGURED=1 only silences upstream's "undocumented build method" notice in
# private/common.h. Feature selection stays explicit: the portable reference files
# above plus the optional x86 SIMD files below, nothing probed by configure.
target_compile_definitions(bale_sodium_static PRIVATE CONFIGURED=1)
target_include_directories(bale_sodium_static SYSTEM PUBLIC
    ${BALE_SODIUM_SOURCE_DIR}/include
    ${BALE_SODIUM_SOURCE_DIR}/include/sodium
    ${CMAKE_CURRENT_BINARY_DIR}/sodium_include
)
target_include_directories(bale_sodium_static PRIVATE
    ${BALE_SODIUM_SOURCE_DIR}/include/sodium
    ${BALE_SODIUM_SOURCE_DIR}/randombytes/sysrandom
    ${CMAKE_CURRENT_BINARY_DIR}/sodium_include/sodium
)
# NOTE: version.h is generated by upstream's configure step; bale generates the same
# file from the shipped template so no configured tree is needed.
set(BALE_SODIUM_VERSION "1.0.20")
set(SODIUM_LIBRARY_VERSION_MAJOR 26)
set(SODIUM_LIBRARY_VERSION_MINOR 2)
set(SODIUM_LIBRARY_MINIMAL_DEF "")
configure_file(
    ${BALE_SODIUM_SOURCE_DIR}/include/sodium/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/sodium_include/sodium/version.h
    @ONLY
)
if(UNIX)
    # NOTE: these unlock libsodium's own mmap/mlock and pthread paths. Without them
    # the code still runs, but secret storage would lose guard pages and locking.
    target_compile_definitions(bale_sodium_static PRIVATE HAVE_SYS_MMAN_H HAVE_MLOCK HAVE_PTHREAD)
    find_package(Threads REQUIRED)
    target_link_libraries(bale_sodium_static PUBLIC Threads::Threads)
endif()
if(WIN32)
    target_link_libraries(bale_sodium_static PRIVATE advapi32)
endif()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|x86|i[3-6]86)$")
    # NOTE: on x86 the runtime dispatchers pick the fastest compiled-in back end, so
    # the SIMD sources below must be present wherever the feature macros are defined.
    # GCC and Clang get the macros explicitly with per-file ISA flags; MSVC defines
    # the macros itself in private/common.h, so it only needs the files with /arch
    # flags (except poly1305_sse2, which needs 128-bit integers MSVC lacks).
    set(BALE_SODIUM_SIMD_COMMON
        crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c
        crypto_generichash/blake2b/ref/blake2b-compress-sse41.c
        crypto_generichash/blake2b/ref/blake2b-compress-avx2.c
        crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c
        crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c
        crypto_pwhash/argon2/argon2-fill-block-ssse3.c
        crypto_pwhash/argon2/argon2-fill-block-avx2.c
        crypto_pwhash/argon2/argon2-fill-block-avx512f.c
        crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c
        crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c
    )
    list(TRANSFORM BALE_SODIUM_SIMD_COMMON PREPEND "${BALE_SODIUM_SOURCE_DIR}/")
    target_sources(bale_sodium_static PRIVATE ${BALE_SODIUM_SIMD_COMMON})
    if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$" AND NOT MSVC)
        target_compile_definitions(bale_sodium_static PRIVATE
            HAVE_TI_MODE
            HAVE_EMMINTRIN_H
            HAVE_TMMINTRIN_H
            HAVE_SMMINTRIN_H
            HAVE_AVX2INTRIN_H
            HAVE_AVX512FINTRIN_H
        )
        target_sources(bale_sodium_static PRIVATE
            ${BALE_SODIUM_SOURCE_DIR}/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c
        )
        set_source_files_properties(
            ${BALE_SODIUM_SOURCE_DIR}/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c
            ${BALE_SODIUM_SOURCE_DIR}/crypto_generichash/blake2b/ref/blake2b-compress-avx2.c
            ${BALE_SODIUM_SOURCE_DIR}/crypto_pwhash/argon2/argon2-fill-block-avx2.c
            ${BALE_SODIUM_SOURCE_DIR}/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c
            PROPERTIES COMPILE_OPTIONS "-mavx2"
        )
        set_source_files_properties(
            ${BALE_SODIUM_SOURCE_DIR}/crypto_pwhash/argon2/argon2-fill-block-avx512f.c
            PROPERTIES COMPILE_OPTIONS "-mavx512f"
        )
        set_source_files_properties(
            ${BALE_SODIUM_SOURCE_DIR}/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c
            ${BALE_SODIUM_SOURCE_DIR}/crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c
            ${BALE_SODIUM_SOURCE_DIR}/crypto_pwhash/argon2/argon2-fill-block-ssse3.c
            PROPERTIES COMPILE_OPTIONS "-mssse3"
        )
        set_source_files_properties(
            ${BALE_SODIUM_SOURCE_DIR}/crypto_generichash/blake2b/ref/blake2b-compress-sse41.c
            PROPERTIES COMPILE_OPTIONS "-msse4.1"
        )
    endif()
    if(MSVC)
        set_source_files_properties(
            ${BALE_SODIUM_SOURCE_DIR}/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c
            ${BALE_SODIUM_SOURCE_DIR}/crypto_generichash/blake2b/ref/blake2b-compress-avx2.c
            ${BALE_SODIUM_SOURCE_DIR}/crypto_pwhash/argon2/argon2-fill-block-avx2.c
            ${BALE_SODIUM_SOURCE_DIR}/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c
            PROPERTIES COMPILE_OPTIONS "/arch:AVX2"
        )
        set_source_files_properties(
            ${BALE_SODIUM_SOURCE_DIR}/crypto_pwhash/argon2/argon2-fill-block-avx512f.c
            PROPERTIES COMPILE_OPTIONS "/arch:AVX512"
        )
    endif()
endif()
target_link_libraries(bale_sodium INTERFACE bale_sodium_static)
