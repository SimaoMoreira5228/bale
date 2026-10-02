add_library(bale_security STATIC
    archive_path.cpp
    case_fold.cpp
)
target_link_libraries(bale_security
    PUBLIC bale_base
    PRIVATE bale_warnings
)
