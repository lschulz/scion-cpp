cmake_minimum_required(VERSION 3.28)

# =========
# ScitraTUN
# =========

if (LINUX)
set(SRC_SCITRA_TUN
    "src/packet.cpp"
    "src/translator.cpp"
    "src/scitra-tun/error_codes.cpp"
    "src/scitra-tun/main_tun.cpp"
    "src/scitra-tun/netlink.cpp"
    "src/scitra-tun/scitra_tun.cpp"
    "src/scitra-tun/sys_net.cpp"
    "src/scitra-tun/tui.cpp"
)

add_executable(scitra-tun ${SRC_SCITRA_TUN})
target_include_directories(scitra-tun PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_link_libraries(scitra-tun PRIVATE
    scion-cpp
    CLI11::CLI11
    spdlog::spdlog
    uring
    mnl
    imtui
    imtui-ncurses
)
target_compile_definitions(scitra-tun PRIVATE
    BOOST_ASIO_HAS_IO_URING=1
    SCION_NO_DEBUG=1
)
endif(LINUX)

# ==========
# Unit Tests
# ==========

set(SRC_SCITRA_TEST
    "src/packet.cpp"
    "src/translator.cpp"
    "tests/main.cpp"
    "tests/test_translation.cpp"
    "${CMAKE_SOURCE_DIR}/tests/utilities.cpp"
)

add_executable(scitra-tests ${SRC_SCITRA_TEST})
target_include_directories(scitra-tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${CMAKE_SOURCE_DIR}/tests"
)
target_link_libraries(scitra-tests PRIVATE gtest gmock scion-cpp)

# =====
# Tools
# =====

add_subdirectory(tools/scion2ip)
