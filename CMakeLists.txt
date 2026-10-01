cmake_minimum_required(VERSION 3.25)

project(bale VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(BALE_BUILD_TESTS "Build the bale test suite" ${PROJECT_IS_TOP_LEVEL})
option(BALE_WERROR "Treat compiler warnings as errors" OFF)

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

add_subdirectory(src)

if(BALE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
