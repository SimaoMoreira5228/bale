add_library(bale_cli STATIC
    archive_commands.cpp
    terminal_text.cpp
)
target_link_libraries(bale_cli
    PUBLIC bale_formats
    PRIVATE bale_warnings
)

add_executable(bale
    main.cpp
)
target_link_libraries(bale PRIVATE
    bale_cli
    bale_warnings
)
