include(FetchContent)

set(DOCTEST_NO_INSTALL ON)
set(DOCTEST_WITH_TESTS OFF)
FetchContent_Declare(doctest
    URL https://github.com/doctest/doctest/archive/refs/tags/v2.5.3.tar.gz
    URL_HASH SHA256=174ebc4e769928959614789c5b4e9c3d0a0f81a62bb608756b127bfebfb21331
)
FetchContent_MakeAvailable(doctest)
include(${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)

add_executable(bale_tests
    base/checked_test.cpp
    io/byte_reader_test.cpp
    io/file_test.cpp
)
target_link_libraries(bale_tests PRIVATE
    bale_io
    bale_warnings
    doctest::doctest_with_main
)
doctest_discover_tests(bale_tests)
