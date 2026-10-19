add_library(bale_formats_compressed STATIC
    output.cpp
    stream.cpp
)
target_link_libraries(bale_formats_compressed
    PUBLIC bale_base bale_checksum bale_codecs bale_formats_bzip2 bale_formats_gzip bale_formats_xz bale_formats_zstd bale_io
    PRIVATE bale_warnings
)
