add_subdirectory(gzip)
add_subdirectory(tar)
add_subdirectory(zip)

add_library(bale_formats STATIC
    detect.cpp
)
target_link_libraries(bale_formats
    PUBLIC bale_format bale_formats_tar bale_formats_zip bale_io
    PRIVATE bale_warnings
)
