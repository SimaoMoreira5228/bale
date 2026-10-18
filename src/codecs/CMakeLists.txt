add_library(bale_codecs STATIC
    bzip2_decoder.cpp
    deflate_encoder.cpp
    inflater.cpp
    lz4_frame.cpp
    xz_decoder.cpp
    zstd_decoder.cpp
    zstd_encoder.cpp
)
target_link_libraries(bale_codecs
    PUBLIC bale_base
    PRIVATE bale_warnings bale_bz2 bale_lz4 bale_lzma bale_zlib_ng bale_zstd
)
