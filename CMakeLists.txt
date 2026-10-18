cmake_minimum_required(VERSION 3.25)

project(bale VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BALE_BUILD_TESTS "Build the bale test suite" ${PROJECT_IS_TOP_LEVEL})
option(BALE_BUILD_BENCHMARKS "Build the bale micro-benchmarks" OFF)
option(BALE_WERROR "Treat compiler warnings as errors" OFF)
option(
    BALE_LINK_COMPILE_COMMANDS
    "Link compile_commands.json from this build into the source tree for clangd"
    ${PROJECT_IS_TOP_LEVEL}
)

if(BALE_LINK_COMPILE_COMMANDS)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    file(
        CREATE_LINK
        ${PROJECT_BINARY_DIR}/compile_commands.json
        ${PROJECT_SOURCE_DIR}/compile_commands.json
        RESULT link_result
        SYMBOLIC
    )
    if(NOT link_result EQUAL 0)
        message(WARNING "Could not link compile_commands.json into the source tree: ${link_result}")
    endif()
endif()

add_library(bale_warnings INTERFACE)
if(MSVC)
    target_compile_options(bale_warnings INTERFACE
        /W4
        /permissive-
        $<$<BOOL:${BALE_WERROR}>:/WX>
    )
else()
    target_compile_options(bale_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wold-style-cast
        -Wnon-virtual-dtor
        $<$<BOOL:${BALE_WERROR}>:-Werror>
    )
endif()

if(MINGW AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # WORKAROUND: GCC spills AVX registers assuming 32-byte stack alignment, which the Windows x64
    # ABI does not guarantee (GCC bug 54412); the bundled codecs crash on their AVX2 paths.
    add_compile_options(-Wa,-muse-unaligned-vector-move)
endif()

include(cmake/Dependencies.cmake)

add_subdirectory(src)

if(BALE_BUILD_BENCHMARKS)
    add_subdirectory(bench)
endif()

if(BALE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
