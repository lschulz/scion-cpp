cmake_minimum_required(VERSION 3.28)

# ====================
# Scitra mptcpd Plugin
# ====================
# TODO: Add sudo apt install libmptcpd3-dev to dependencies
# TODO: Add ELL to dependencies (libell-dev >= v0.30)

if (LINUX)

add_library(scitra-mptcpd SHARED)
target_sources(scitra-mptcpd PRIVATE
    "scitra_plugin.c"
    "scitra_plugin.cpp"
)
target_include_directories(scitra-mptcpd PRIVATE
    "${CMAKE_SOURCE_DIR}/deps/mptcpd/include"
    "${CMAKE_SOURCE_DIR}/scitra/include"
)
target_link_libraries(scitra-tun PRIVATE
    scion-cpp
)
set_target_properties(scitra-mptcpd PROPERTIES
    PREFIX ""
    OUTPUT_NAME "scitra"
)

endif (LINUX)
