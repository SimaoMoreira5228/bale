add_library(bale_archive STATIC
    cdc.cpp
    chunk.cpp
    chunk_codec.cpp
    chunk_pipeline.cpp
    commit.cpp
    compactor.cpp
    compactor_encrypted.cpp
    encrypted.cpp
    index.cpp
    manifest.cpp
    reader.cpp
    reader_commit.cpp
    reader_encrypted.cpp
    writer.cpp
    writer_chunks.cpp
    writer_encrypted.cpp
    writer_profile.cpp
)
target_link_libraries(bale_archive
    PUBLIC bale_base bale_checksum bale_format bale_fswalk bale_io bale_security
    PRIVATE bale_codecs bale_crypto bale_warnings
)
