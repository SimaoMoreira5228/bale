add_library(bale_formats_tar STATIC
    header.cpp
    reader.cpp
)
target_link_libraries(bale_formats_tar
    PUBLIC bale_io bale_base
    PRIVATE bale_warnings
)
