add_library(bale_formats_wim STATIC
    header.cpp
    lookup.cpp
    metadata.cpp
    reader.cpp
    resource.cpp
    xml.cpp
)
target_link_libraries(bale_formats_wim
    PUBLIC bale_base bale_io
    PRIVATE bale_warnings
)
