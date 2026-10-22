add_library(bale_parity STATIC
    reed_solomon.cpp
)
target_link_libraries(bale_parity
    PUBLIC bale_base
    PRIVATE bale_warnings
)
