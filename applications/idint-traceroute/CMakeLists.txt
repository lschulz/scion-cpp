cmake_minimum_required(VERSION 3.28)

set(IDINT_TRACEROUTE_SRC
    "main.cpp"
    "tables.cpp"
)
add_executable(idint-traceroute ${IDINT_TRACEROUTE_SRC})
target_link_libraries(idint-traceroute PRIVATE scion-cpp CLI11::CLI11)
