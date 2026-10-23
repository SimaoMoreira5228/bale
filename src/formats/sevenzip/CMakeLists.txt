add_library(bale_formats_sevenzip STATIC
    coding.cpp
    encode.cpp
    files.cpp
    folder.cpp
    header.cpp
    reader.cpp
    writer.cpp
)
target_link_libraries(bale_formats_sevenzip
    PUBLIC bale_base bale_checksum bale_codecs bale_io bale_lzma
    PRIVATE bale_bz2 bale_warnings
)
