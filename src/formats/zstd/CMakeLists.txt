add_library(bale_formats_zstd STATIC
    stream.cpp
)
target_link_libraries(bale_formats_zstd
    PUBLIC bale_base bale_codecs bale_io
    PRIVATE bale_warnings
)
