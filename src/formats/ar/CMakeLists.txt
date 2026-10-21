add_library(bale_formats_ar STATIC
    header.cpp
    reader.cpp
)
target_link_libraries(bale_formats_ar
    PUBLIC bale_base bale_io
    PRIVATE bale_warnings
)
