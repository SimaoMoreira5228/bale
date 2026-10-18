add_subdirectory(bzip2)
add_subdirectory(compressed)
add_subdirectory(gzip)
add_subdirectory(sevenzip)
add_subdirectory(tar)
add_subdirectory(xz)
add_subdirectory(zip)
add_subdirectory(zstd)

add_library(bale_formats STATIC
    detect.cpp
)
target_link_libraries(bale_formats
    PUBLIC bale_format bale_formats_compressed bale_formats_sevenzip bale_formats_tar bale_formats_zip bale_io
    PRIVATE bale_warnings
)
