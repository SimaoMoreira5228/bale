option(
    BALE_USE_SYSTEM_CODECS
    "Link system zlib-ng, zstd, LZ4 and BLAKE3 instead of building pinned sources"
    OFF
)

add_library(bale_zlib_ng INTERFACE)
add_library(bale_zstd INTERFACE)
add_library(bale_lz4 INTERFACE)
add_library(bale_blake3 INTERFACE)
add_library(bale_lzma INTERFACE)
add_library(bale_bz2 INTERFACE)

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
FetchContent_Declare(xz
    URL https://github.com/tukaani-project/xz/releases/download/v5.8.4/xz-5.8.4.tar.gz
    URL_HASH SHA256=0014c7886930454fe8bd4228665b51af55eeae560ea135c9c4cd33f55b2591d9
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

    FetchContent_MakeAvailable(zlib_ng zstd lz4 blake3 xz)
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
# NOTE: liblzma's CMake target does not expose its API headers, so bale adds them
# explicitly instead of picking up whatever lzma.h the system happens to provide.
FetchContent_GetProperties(xz SOURCE_DIR XZ_SOURCE_DIR)
target_include_directories(bale_lzma SYSTEM INTERFACE ${XZ_SOURCE_DIR}/src/liblzma/api)
target_link_libraries(bale_lzma INTERFACE liblzma)
