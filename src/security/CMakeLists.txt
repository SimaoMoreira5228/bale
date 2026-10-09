add_library(bale_security STATIC
    archive_path.cpp
    case_fold.cpp
    unicode_table.cpp
)
target_link_libraries(bale_security
    PUBLIC bale_base
    PRIVATE bale_warnings
)
