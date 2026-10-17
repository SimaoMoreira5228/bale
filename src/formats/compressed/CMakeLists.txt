add_library(bale_formats_compressed STATIC
    stream.cpp
)
target_link_libraries(bale_formats_compressed
    PUBLIC bale_base bale_formats_gzip bale_formats_zstd bale_io
    PRIVATE bale_warnings
)
