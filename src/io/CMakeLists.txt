add_library(bale_io STATIC
    file.cpp
)
target_link_libraries(bale_io
    PUBLIC bale_base
    PRIVATE bale_warnings
)
if(NOT WIN32)
    target_compile_definitions(bale_io PRIVATE _FILE_OFFSET_BITS=64)
endif()
