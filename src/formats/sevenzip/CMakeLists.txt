add_library(bale_formats_sevenzip STATIC
    branch.cpp
    coding.cpp
    encode.cpp
    files.cpp
    folder.cpp
    folder_filter.cpp
    header.cpp
    raw_lzma.cpp
    reader.cpp
    writer.cpp
)
target_link_libraries(bale_formats_sevenzip
    PUBLIC bale_base bale_checksum bale_codecs bale_io bale_lzma
    PRIVATE bale_bz2 bale_warnings
)
