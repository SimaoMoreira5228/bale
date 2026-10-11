add_executable(bale_bench_crc crc_bench.cpp)
target_link_libraries(bale_bench_crc PRIVATE bale_checksum bale_warnings)

add_executable(bale_bench_codecs codec_bench.cpp)
target_link_libraries(bale_bench_codecs PRIVATE bale_archive bale_codecs bale_io bale_warnings)
if(WIN32)
    target_link_libraries(bale_bench_codecs PRIVATE psapi)
endif()
