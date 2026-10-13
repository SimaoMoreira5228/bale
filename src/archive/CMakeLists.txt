add_library(bale_archive STATIC
    chunk.cpp
    chunk_codec.cpp
    chunk_pipeline.cpp
    commit.cpp
    compactor.cpp
    index.cpp
    manifest.cpp
    reader.cpp
    reader_commit.cpp
    tree_walk.cpp
    writer.cpp
    writer_chunks.cpp
    writer_profile.cpp
)
target_link_libraries(bale_archive
    PUBLIC bale_base bale_checksum bale_format bale_io bale_security
    PRIVATE bale_codecs bale_warnings
)
