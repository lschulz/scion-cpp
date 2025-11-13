cmake_minimum_required(VERSION 3.28)

# ========
# scion2ip
# ========

set(SRC_SCION2IP
    "src/scion2ip.cpp"
    "${CMAKE_SOURCE_DIR}/src/addr/endpoint.cpp"
    "${CMAKE_SOURCE_DIR}/src/addr/generic_ip.cpp"
    "${CMAKE_SOURCE_DIR}/src/addr/isd_asn.cpp"
    "${CMAKE_SOURCE_DIR}/src/error_codes.cpp"
)

add_executable(scion2ip ${SRC_SCION2IP})
target_include_directories(scion2ip PRIVATE "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(scion2ip PRIVATE CLI11::CLI11)
