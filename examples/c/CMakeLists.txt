cmake_minimum_required(VERSION 3.22)

# ============
# Dependencies
# ============

if (NOT WIN32)
    find_package(Curses)
endif()

# ==========
# echo-udp-c
# ==========

SET(SRC_ECHO_UDP_C
    "echo_udp/main.c"
    "include/console.c"
    "include/format.c"
)

add_executable(echo-udp-c ${SRC_ECHO_UDP_C})
target_include_directories(echo-udp-c PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(echo-udp-c PRIVATE scion-c)

if (NOT WIN32)
    target_include_directories(echo-udp-c PRIVATE ${CURSES_INCLUDE_DIR})
    target_link_libraries(echo-udp-c PRIVATE ${CURSES_LIBRARIES})
endif()

# ================
# echo-udp-async-c
# ================

SET(SRC_ECHO_UDP_ASYNC_C
    "echo_udp_async/main.c"
    "include/console.c"
    "include/format.c"
)

add_executable(echo-udp-async-c ${SRC_ECHO_UDP_ASYNC_C})
target_include_directories(echo-udp-async-c PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(echo-udp-async-c PRIVATE scion-c)

if (NOT WIN32)
    target_include_directories(echo-udp-async-c PRIVATE ${CURSES_INCLUDE_DIR})
    target_link_libraries(echo-udp-async-c PRIVATE ${CURSES_LIBRARIES})
endif()
