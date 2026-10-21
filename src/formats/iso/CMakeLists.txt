add_library(bale_formats_iso STATIC
    directory.cpp
    eltorito.cpp
    header.cpp
    reader.cpp
    susp.cpp
    volume.cpp
)
target_link_libraries(bale_formats_iso
    PUBLIC bale_base bale_io
    PRIVATE bale_warnings
)
