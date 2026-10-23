add_library(bale_base INTERFACE)
target_include_directories(bale_base INTERFACE ${PROJECT_SOURCE_DIR}/src)
target_compile_features(bale_base INTERFACE cxx_std_23)
if(WIN32)
    target_compile_definitions(bale_base INTERFACE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()
if(MINGW)
    # NOTE: MinGW keeps <print>'s terminal helpers in the experimental
    # library; without it bale's console output fails to link.
    target_link_libraries(bale_base INTERFACE stdc++exp)
endif()
target_link_libraries(bale_base INTERFACE bale_expected)
