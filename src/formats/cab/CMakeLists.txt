add_library(bale_formats_cab STATIC
    header.cpp
    lzx.cpp
    reader.cpp
    session.cpp
    tree.cpp
)
target_link_libraries(bale_formats_cab
    PUBLIC bale_base bale_codecs bale_io
    PRIVATE bale_warnings
)
