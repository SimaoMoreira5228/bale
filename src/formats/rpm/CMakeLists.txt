add_library(bale_formats_rpm STATIC
    header.cpp
    reader.cpp
)
target_link_libraries(bale_formats_rpm
    PUBLIC bale_base bale_formats_compressed bale_formats_cpio bale_io
    PRIVATE bale_warnings
)
