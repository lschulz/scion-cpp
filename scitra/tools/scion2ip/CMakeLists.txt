cmake_minimum_required(VERSION 3.28)

# ========
# scion2ip
# ========

add_executable(scion2ip)
target_sources(scion2ip PRIVATE
    "src/scion2ip.cpp"
    "${CMAKE_SOURCE_DIR}/src/addr/endpoint.cpp"
    "${CMAKE_SOURCE_DIR}/src/addr/generic_ip.cpp"
    "${CMAKE_SOURCE_DIR}/src/addr/isd_asn.cpp"
    "${CMAKE_SOURCE_DIR}/src/error_codes.cpp"
)
target_include_directories(scion2ip PRIVATE "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(scion2ip PRIVATE CLI11::CLI11)

set_target_properties(scion2ip PROPERTIES
    OUTPUT_NAME "scion2ip"
    DEBUG_POSTFIX "-debug"
)
install(TARGETS scion2ip RUNTIME)
