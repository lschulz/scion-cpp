cmake_minimum_required(VERSION 3.22)

# ============
# Dependencies
# ============

if (NOT WIN32)
    find_package(Curses)
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/deps/CLI11)

# ========
# echo-udp
# ========

SET(SRC_ECHO_UDP
    "echo_udp/main.cpp"
    "include/format.cpp"
)
if (NOT WIN32)
list(APPEND SRC_ECHO_UDP "include/console.cpp")
endif()

add_executable(echo-udp ${SRC_ECHO_UDP})
target_include_directories(echo-udp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(echo-udp PRIVATE scion-cpp CLI11::CLI11)

if (NOT WIN32)
    target_include_directories(echo-udp PRIVATE ${CURSES_INCLUDE_DIR})
    target_link_libraries(echo-udp PRIVATE ${CURSES_LIBRARIES})
endif()

# ==============
# echo-udp-async
# ==============

SET(SRC_ECHO_UDP_ASYNC
    "echo_udp_async/main.cpp"
    "include/format.cpp"
)
add_executable(echo-udp-async ${SRC_ECHO_UDP_ASYNC})
target_include_directories(echo-udp-async PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(echo-udp-async PRIVATE scion-cpp CLI11::CLI11)

# ==========
# traceroute
# ==========

SET(SRC_TRACEROUTE
    "traceroute/main.cpp"
    "include/format.cpp"
)
add_executable(traceroute ${SRC_TRACEROUTE})
target_include_directories(traceroute PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(traceroute PRIVATE scion-cpp CLI11::CLI11)

# ====
# pmtu
# ====

SET(SRC_PMTU
    "pmtu/main.cpp"
    "include/format.cpp"
)
add_executable(pmtu ${SRC_PMTU})
target_include_directories(pmtu PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(pmtu PRIVATE scion-cpp CLI11::CLI11)

# ========
# resolver
# ========

SET(SRC_RESOLVER
    "resolver/main.cpp"
)
add_executable(resolver ${SRC_RESOLVER})
target_include_directories(resolver PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(resolver PRIVATE scion-cpp CLI11::CLI11)

# ==========
# C examples
# ==========

add_subdirectory(c)
