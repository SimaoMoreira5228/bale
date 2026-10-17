add_library(bale_format STATIC
    envelope.cpp
    record.cpp
    tlv.cpp
)
target_link_libraries(bale_format
    PUBLIC bale_base bale_checksum
    PRIVATE bale_warnings
)
