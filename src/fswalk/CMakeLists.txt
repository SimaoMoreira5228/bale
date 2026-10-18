add_library(bale_fswalk STATIC
    tree_walker.cpp
)
target_link_libraries(bale_fswalk
    PUBLIC bale_base bale_io bale_security
    PRIVATE bale_warnings
)
