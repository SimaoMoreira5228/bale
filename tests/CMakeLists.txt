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
    archive/hardlink_order_test.cpp
    archive/brotli_chunk_test.cpp
    archive/cdc_test.cpp
    archive/compression_test.cpp
    archive/encrypted_test.cpp
    archive/encrypted_attack_test.cpp
    archive/lzma2_chunk_test.cpp
    archive/pipeline_test.cpp
    archive/schema_test.cpp
    archive/signature_test.cpp
    archive/snapshot_test.cpp
    base/checked_test.cpp
    checksum/blake3_test.cpp
    checksum/crc_test.cpp
    cli/single_file_test.cpp
    cli/rpm_cli_test.cpp
    cli/repair_cli_test.cpp
    cli/terminal_text_test.cpp
    cli/wim_cli_test.cpp
    codecs/brotli_test.cpp
    codecs/decoders_test.cpp
    codecs/lzma2_test.cpp
    codecs/lz4_frame_test.cpp
    crypto/aead_test.cpp
    crypto/kdf_test.cpp
    crypto/secrets_test.cpp
    crypto/slots_test.cpp
    extract/extractor_test.cpp
    format/envelope_test.cpp
    format/tlv_test.cpp
    formats/bzip2/stream_test.cpp
    formats/xz/stream_test.cpp
    fswalk/tree_walker_test.cpp
    formats/detect_test.cpp
    formats/wim/reader_test.cpp
    formats/wim/refuse_test.cpp
    formats/ar/reader_test.cpp
    formats/cab/decoder_test.cpp
    formats/cab/reader_test.cpp
    formats/cab/tree_test.cpp
    formats/cpio/reader_test.cpp
    formats/gzip/stream_test.cpp
    formats/iso/reader_test.cpp
    formats/iso/refuse_test.cpp
    formats/tar/compressed_reader_test.cpp
    formats/rpm/reader_test.cpp
    formats/tar/hardlink_order_test.cpp
    formats/tar/header_test.cpp
    formats/tar/reader_test.cpp
    formats/tar/writer_test.cpp
    formats/sevenzip/reader_test.cpp
    formats/zip/reader_test.cpp
    formats/zip/writer_test.cpp
    formats/zstd/stream_test.cpp
    io/byte_reader_test.cpp
    io/file_test.cpp
    parity/reed_solomon_test.cpp
    parity/parity_adversarial_test.cpp
    parity/parity_repair_test.cpp
    parity/parity_roundtrip_test.cpp
    parity/parity_wire_test.cpp
    reference/reference_test.cpp
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
    bale_crypto
    bale_extract
    bale_format
    bale_formats_compressed
    bale_formats_gzip
    bale_formats_iso
    bale_formats_sevenzip
    bale_formats_tar
    bale_formats_zip
    bale_formats_zstd
    bale_fswalk
    bale_io
    bale_security
    bale_formats_ar
    bale_formats_cab
    bale_formats_cpio
    bale_formats_rpm
    bale_formats_wim
    bale_brotli
    bale_bz2
    bale_lz4
    bale_lzma
    bale_parity
    bale_sodium
    bale_warnings
    bale_zlib_ng
    bale_zstd
    doctest::doctest_with_main
)
doctest_discover_tests(bale_tests)
target_compile_definitions(
    bale_tests PRIVATE REFERENCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/reference"
)
target_compile_definitions(
    bale_tests PRIVATE FORMAT_GOLDEN_DIR="${CMAKE_CURRENT_SOURCE_DIR}/formats"
)

find_package(Python3 3.10 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND AND NOT CMAKE_CROSSCOMPILING)
    add_test(
        NAME interoperability.cli
        COMMAND Python3::Interpreter -I ${CMAKE_CURRENT_SOURCE_DIR}/interoperability/cli_test.py
            $<TARGET_FILE:bale>
    )
    add_test(
        NAME reference.differential
        COMMAND Python3::Interpreter -I ${CMAKE_CURRENT_SOURCE_DIR}/reference/differential_test.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/reference
    )
endif()
