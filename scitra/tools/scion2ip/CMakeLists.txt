cmake_minimum_required(VERSION 3.28)

# ========
# scion2ip
# ========

set(scion2ip_VERSION_MAJOR 0)
set(scion2ip_VERSION_MINOR 0)
set(scion2ip_VERSION_PATCH 1)
set(scion2ip_VERSION
    "${scion2ip_VERSION_MAJOR}.${scion2ip_VERSION_MINOR}.${scion2ip_VERSION_PATCH}${VERSION_TAG}")
configure_file(src/version.cpp.in version.cpp)

add_executable(scion2ip)
target_sources(scion2ip PRIVATE
    "src/scion2ip.cpp"
    "${CMAKE_CURRENT_BINARY_DIR}/version.cpp"
)
target_include_directories(scion2ip PRIVATE "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(scion2ip PRIVATE CLI11::CLI11 scion-cpp)

set_target_properties(scion2ip PROPERTIES
    OUTPUT_NAME "scion2ip"
    DEBUG_POSTFIX "-d"
)
install(TARGETS scion2ip
    COMPONENT TOOLS
    RUNTIME
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/scion2ip.1.gz"
    COMPONENT TOOLS
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/man/man1/"
)
