set(bale_fuzz_targets
    fuzz_archive_path
    fuzz_bzip2
    fuzz_codecs
    fuzz_crypto_aead
    fuzz_crypto_slots
    fuzz_detect
    fuzz_gzip
    fuzz_native_archive
    fuzz_native_records
    fuzz_sevenzip
    fuzz_tar
    fuzz_terminal_text
    fuzz_tlv
    fuzz_xz
    fuzz_zip
    fuzz_zstd
)

foreach(target IN LISTS bale_fuzz_targets)
    add_executable(${target} ${target}.cpp)
    target_include_directories(${target} PRIVATE ${PROJECT_SOURCE_DIR}/tests)
    target_link_options(${target} PRIVATE -fsanitize=fuzzer)
    target_link_libraries(${target} PRIVATE
        bale_archive
        bale_cli
        bale_codecs
        bale_crypto
        bale_format
        bale_formats
        bale_formats_bzip2
        bale_formats_compressed
        bale_formats_gzip
        bale_formats_sevenzip
        bale_formats_tar
        bale_formats_xz
        bale_formats_zip
        bale_formats_zstd
        bale_io
        bale_security
        bale_warnings
    )
endforeach()
