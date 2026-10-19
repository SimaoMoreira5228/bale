add_library(bale_crypto STATIC
    crypto.cpp
    secrets.cpp
)
target_link_libraries(bale_crypto
    PUBLIC bale_base
    PRIVATE bale_sodium bale_warnings
)
