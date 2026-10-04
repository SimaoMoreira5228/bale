option(BALE_USE_SYSTEM_CODECS "Link system zlib-ng and zstd instead of building pinned sources" OFF)

add_library(bale_zlib_ng INTERFACE)
add_library(bale_zstd INTERFACE)

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

    FetchContent_MakeAvailable(zlib_ng zstd)
endblock()

target_link_libraries(bale_zlib_ng INTERFACE zlib-ng::zlib)
target_link_libraries(bale_zstd INTERFACE libzstd_static)
