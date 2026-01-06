cmake_minimum_required(VERSION 3.28)

# =========
# ScitraTUN
# =========

if (LINUX)
find_package(PkgConfig)
pkg_check_modules(libcap REQUIRED IMPORTED_TARGET libcap)
pkg_check_modules(libpsx REQUIRED IMPORTED_TARGET libpsx)

configure_file("src/scitra-tun/version.cpp.in" "version.cpp")

add_executable(scitra-tun)
target_sources(scitra-tun PRIVATE
    "src/packet.cpp"
    "src/translator.cpp"
    "src/scitra-tun/error_codes.cpp"
    "src/scitra-tun/main_tun.cpp"
    "src/scitra-tun/netlink.cpp"
    "src/scitra-tun/scitra_tun.cpp"
    "src/scitra-tun/socket.cpp"
    "src/scitra-tun/sys_net.cpp"
    "src/scitra-tun/tui.cpp"
    "${CMAKE_CURRENT_BINARY_DIR}/version.cpp"
)
target_include_directories(scitra-tun PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_link_libraries(scitra-tun PRIVATE
    scion-cpp
    CLI11::CLI11
    spdlog::spdlog
    mnl
    imtui
    imtui-ncurses
    PkgConfig::libcap
    PkgConfig::libpsx
)
target_compile_definitions(scitra-tun PRIVATE
    SCION_NO_DEBUG=1
    PERF_DEBUG=$<IF:$<CONFIG:Release>,0,1>
)
set_target_properties(scitra-tun PROPERTIES
    OUTPUT_NAME "scitra-tun"
    DEBUG_POSTFIX "-d"
)
install(TARGETS scitra-tun
    COMPONENT SCITRA_TUN
    RUNTIME
)
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/install/scitra-tun/scitra-tun.conf"
    "${CMAKE_CURRENT_SOURCE_DIR}/install/scitra-tun/scitra-policy.json"
    COMPONENT SCITRA_TUN
    # Only install to an absolute path if CPACK_SET_DESTDIR is requested explicitly.
    DESTINATION $<IF:$<BOOL:${CPACK_SET_DESTDIR}>,/etc/scion/,${CMAKE_INSTALL_SYSCONFDIR}/scion/>
)
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/install/scitra-tun/debian/config-dns"
    "${CMAKE_CURRENT_SOURCE_DIR}/install/scitra-tun/debian/config-routes"
    COMPONENT SCITRA_TUN
    PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ WORLD_READ
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/scitra-tun/"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/install/scitra-tun/debian/scitra-tun.service"
    COMPONENT SCITRA_TUN
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/systemd/system/"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/scitra-tun.8.gz"
    COMPONENT SCITRA_TUN
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/man/man8/"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/scitra-policy.json.5.gz"
    COMPONENT SCITRA_TUN
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/man/man5/"
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
