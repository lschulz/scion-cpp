cmake_minimum_required(VERSION 3.28)

project(scitra-tun
    VERSION 0.1.0
    DESCRIPTION "SCION-IP Translator for TUN/TAP device"
    HOMEPAGE_URL "https://github.com/lschulz/scion-cpp"
    LANGUAGES CXX
)

option(SCITRA_BUILD_TESTS "Build Scitra-TUN unit tests" ON)
set(SCITRA_SYSTEMD_UNIT_DIR "" CACHE PATH "Installation path for systemd units")

if(PROJECT_IS_TOP_LEVEL)
    list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/../cmake")
    include(CompilerOptions)
    include(VersionTag)
    include(Submodules)
    include(Packaging)
    include(GNUInstallDirs)
    find_package(scion-cpp 0.0.5 REQUIRED)
endif()

if(SCITRA_SYSTEMD_UNIT_DIR)
    set(SYSTEMD_UNIT_DIR "${SCITRA_SYSTEMD_UNIT_DIR}")
elseif(CMAKE_INSTALL_PREFIX STREQUAL "/")
    set(SYSTEMD_UNIT_DIR "usr/lib/systemd/system")
else()
    set(SYSTEMD_UNIT_DIR "lib/systemd/system")
endif()

# ============
# Dependencies
# ============

scion_add_spdlog()
scion_add_imtui()

# =========
# ScitraTUN
# =========

find_package(PkgConfig REQUIRED)
pkg_check_modules(libcap REQUIRED IMPORTED_TARGET libcap)
pkg_check_modules(libpsx REQUIRED IMPORTED_TARGET libpsx)
pkg_check_modules(libsystemd REQUIRED IMPORTED_TARGET libsystemd)
pkg_check_modules(libbsd REQUIRED IMPORTED_TARGET libbsd)

configure_file("src/scitra-tun/version.cpp.in" "version.cpp")

add_executable(scitra-tun)
target_sources(scitra-tun PRIVATE
    "src/crypto.cpp"
    "src/packet.cpp"
    "src/translator.cpp"
    "src/scitra-tun/error_codes.cpp"
    "src/scitra-tun/main_tun.cpp"
    "src/scitra-tun/netlink.cpp"
    "src/scitra-tun/scitra_tun.cpp"
    "src/scitra-tun/service_systemd.cpp"
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
    scion::cpp
    CLI11::CLI11
    spdlog::spdlog
    mnl
    imtui
    imtui-ncurses
    PkgConfig::libcap
    PkgConfig::libpsx
    PkgConfig::libsystemd
    PkgConfig::libbsd
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
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/scion"
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
    DESTINATION "${SYSTEMD_UNIT_DIR}"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/scitra-tun.8.gz"
    COMPONENT SCITRA_TUN
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/man/man8/"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/scitra-policy.json.5.gz"
    COMPONENT SCITRA_TUN
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/man/man5/"
)

# ==========
# Unit Tests
# ==========

if(SCITRA_BUILD_TESTS)
if(TARGET scion_test_utils)
    set(SRC_SCITRA_TEST
        "src/crypto.cpp"
        "src/packet.cpp"
        "src/translator.cpp"
        "tests/main.cpp"
        "tests/test_crypto.cpp"
        "tests/test_packet.cpp"
        "tests/test_translation.cpp"
        "${CMAKE_SOURCE_DIR}/tests/utilities.cpp"
    )

    add_executable(scitra-tests ${SRC_SCITRA_TEST})
    target_include_directories(scitra-tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/tests"
    )
    target_link_libraries(scitra-tests PRIVATE
        gtest gmock scion::cpp scion_test_utils
    )
endif()
endif(SCITRA_BUILD_TESTS)

# =========
# Packaging
# =========

set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/scitra/install/scitra-tun/debian/conffiles"
)
string(CONCAT CPACK_DEBIAN_PACKAGE_RECOMMENDS
    "scion-daemon, "
    "scion++-tools"
)

scion_rpm_conffiles(CPACK_RPM_USER_FILELIST
    "${CMAKE_SOURCE_DIR}/scitra/install/scitra-tun/debian/conffiles"
)
set(CONCAT CPACK_RPM_PACKAGE_SUGGESTS
    "scion-daemon"
    "scion++-tools"
)
scion_configure_cpack(COMPONENTS SCITRA_TUN)
