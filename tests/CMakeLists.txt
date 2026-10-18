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
    archive/archive_test.cpp
    archive/schema_test.cpp
    archive/zstd_test.cpp
    base/checked_test.cpp
    checksum/blake3_test.cpp
    checksum/crc_test.cpp
    cli/single_file_test.cpp
    cli/terminal_text_test.cpp
    codecs/decoders_test.cpp
    extract/extractor_test.cpp
    format/envelope_test.cpp
    format/tlv_test.cpp
    formats/detect_test.cpp
    formats/gzip/stream_test.cpp
    formats/tar/compressed_reader_test.cpp
    formats/tar/header_test.cpp
    formats/tar/reader_test.cpp
    formats/zip/reader_test.cpp
    formats/zstd/stream_test.cpp
    io/byte_reader_test.cpp
    io/file_test.cpp
    security/archive_path_test.cpp
    security/budget_test.cpp
    security/case_fold_test.cpp
)
target_include_directories(bale_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(bale_tests PRIVATE
    bale_archive
    bale_checksum
    bale_cli
    bale_codecs
    bale_extract
    bale_format
    bale_formats_compressed
    bale_formats_gzip
    bale_formats_tar
    bale_formats_zip
    bale_formats_zstd
    bale_io
    bale_security
    bale_warnings
    bale_zlib_ng
    bale_zstd
    doctest::doctest_with_main
)
doctest_discover_tests(bale_tests)

find_package(Python3 3.10 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND AND NOT CMAKE_CROSSCOMPILING)
    add_test(
        NAME interoperability.cli
        COMMAND Python3::Interpreter -I ${CMAKE_CURRENT_SOURCE_DIR}/interoperability/cli_test.py
            $<TARGET_FILE:bale>
    )
endif()
