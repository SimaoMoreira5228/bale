add_library(bale_formats_bzip2 STATIC
    stream.cpp
)
target_link_libraries(bale_formats_bzip2
    PUBLIC bale_base bale_codecs bale_io
    PRIVATE bale_warnings
)
