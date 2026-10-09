add_library(bale_checksum STATIC
    blake3.cpp
    crc.cpp
)
target_link_libraries(bale_checksum
    PUBLIC bale_base
    PRIVATE bale_warnings bale_blake3 bale_zlib_ng
)
