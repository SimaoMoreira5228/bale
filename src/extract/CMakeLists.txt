add_library(bale_extract STATIC
    extractor.cpp
    extractor_posix.cpp
    extractor_windows.cpp
)
target_link_libraries(bale_extract
    PUBLIC bale_base bale_io bale_security
    PRIVATE bale_warnings
)
if(WIN32)
    target_link_libraries(bale_extract PRIVATE ntdll)
endif()
