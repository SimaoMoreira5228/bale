add_library(bale_archive STATIC
    chunk.cpp
    commit.cpp
    index.cpp
    manifest.cpp
    reader.cpp
    reader_commit.cpp
    tree_walk.cpp
    writer.cpp
)
target_link_libraries(bale_archive
    PUBLIC bale_base bale_checksum bale_format bale_io bale_security
    PRIVATE bale_codecs bale_warnings
)
