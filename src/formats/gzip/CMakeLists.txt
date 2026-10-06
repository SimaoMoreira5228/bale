add_library(bale_formats_gzip STATIC
    header.cpp
    stream.cpp
)
target_link_libraries(bale_formats_gzip
    PUBLIC bale_base bale_checksum bale_codecs bale_io
    PRIVATE bale_warnings
)
