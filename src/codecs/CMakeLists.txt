add_library(bale_codecs STATIC
    inflater.cpp
    zstd_decoder.cpp
    zstd_encoder.cpp
)
target_link_libraries(bale_codecs
    PUBLIC bale_base
    PRIVATE bale_warnings bale_zlib_ng bale_zstd
)
