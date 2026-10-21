add_library(bale_formats_cpio STATIC
    header.cpp
    reader.cpp
)
target_link_libraries(bale_formats_cpio
    PUBLIC bale_base bale_io
    PRIVATE bale_warnings
)
