add_library(bale_base INTERFACE)
target_include_directories(bale_base INTERFACE ${PROJECT_SOURCE_DIR}/src)
target_compile_features(bale_base INTERFACE cxx_std_23)
