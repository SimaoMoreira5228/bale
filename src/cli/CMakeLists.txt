add_library(bale_cli STATIC
    archive_commands.cpp
    create_command.cpp
    extract_command.cpp
    terminal_text.cpp
)
target_link_libraries(bale_cli
    PUBLIC bale_archive bale_extract bale_formats
    PRIVATE bale_warnings
)

add_executable(bale
    main.cpp
)
target_link_libraries(bale PRIVATE
    bale_cli
    bale_warnings
)

if(MINGW)
    target_link_options(bale PRIVATE -municode)
endif()

if(MINGW)
    target_link_libraries(bale_cli PUBLIC stdc++exp)
endif()
