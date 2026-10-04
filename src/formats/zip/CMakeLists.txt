add_library(bale_formats_zip STATIC
    central_directory.cpp
    reader.cpp
)
target_link_libraries(bale_formats_zip
    PUBLIC bale_base bale_checksum bale_codecs bale_io
    PRIVATE bale_warnings
)
