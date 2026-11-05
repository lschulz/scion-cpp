cmake_minimum_required(VERSION 3.28)

project(scion-interposer
    VERSION 0.0.5
    DESCRIPTION "Emulates native SCION support in applications that use libc for network I/O"
    HOMEPAGE_URL "https://github.com/lschulz/scion-cpp"
    LANGUAGES C CXX
)

option(INTERPOSER_BUILD_TESTS "Build interposer tests and targets for integration test" ON)

if(PROJECT_IS_TOP_LEVEL)
    list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/../cmake")
    include(CompilerOptions)
    include(Submodules)
    include(Packaging)
    include(GNUInstallDirs)
    find_package(scion-cpp 0.0.5 REQUIRED COMPONENTS c)
endif()

# ============
# Dependencies
# ============

if(NOT TARGET re2::re2)
    find_package(re2 CONFIG QUIET)
endif()
if (NOT TARGET re2::re2)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(re2_pkg REQUIRED IMPORTED_TARGET re2)
    add_library(re2::re2 ALIAS PkgConfig::re2_pkg)
endif()

# ==========
# Interposer
# ==========

add_library(interposer SHARED)
target_sources(interposer PRIVATE
    "src/builtin_selector.cpp"
    "src/control_plane.cpp"
    "src/interposer.cpp"
    "src/libc_interposer.c"
    "src/log.c"
    "src/options.cpp"
    "src/selector.cpp"
)
target_include_directories(interposer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_link_libraries(interposer PRIVATE scion::cpp scion::c-static re2::re2)
target_compile_definitions(interposer PRIVATE
    "$<$<CONFIG:DEBUG>:LOG_CALLS=1>"
)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # g++ sets _GNU_SOURCE for C++ files, make sure it is also set for C
    target_compile_definitions(interposer PUBLIC _GNU_SOURCE=1)
endif()

set_target_properties(interposer PROPERTIES
    OUTPUT_NAME "scion-interposer"
    PREFIX ""
    DEBUG_POSTFIX "d"
    VERSION "${PROJECT_VERSION}"
    SOVERSION "${PROJECT_VERSION_MAJOR}"
)
install(TARGETS interposer
    COMPONENT INTERPOSER
    RUNTIME
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/install/interposer.toml"
    COMPONENT INTERPOSER
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/scion"
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/scion-interposer.7.gz"
    COMPONENT INTERPOSER
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/man/man7/"
)

# =====================
# Default Path Selector
# =====================

add_library(default-selector SHARED
    "src/builtin_selector.cpp"
)
target_include_directories(default-selector PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_link_libraries(default-selector PRIVATE scion::c)
set_target_properties(default-selector PROPERTIES
    PREFIX ""
)

# ==========
# Unit Tests
# ==========

if(INTERPOSER_BUILD_TESTS)
if(TARGET scion_test_utils)
    set(SRC_INTERPOSER_TEST
        "src/builtin_selector.cpp"
        "src/control_plane.cpp"
        "src/interposer.cpp"
        "src/log.c"
        "src/options.cpp"
        "src/selector.cpp"
        "tests/main.cpp"
        "tests/test_get_addr_info.cpp"
        "tests/test_get_name_info.cpp"
        "tests/test_udp_socket.cpp"
    )
    add_executable(interposer-tests ${SRC_INTERPOSER_TEST})
    target_include_directories(interposer-tests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/tests"
    )
    target_link_libraries(interposer-tests PRIVATE
        gtest gmock scion::cpp scion::c scion_test_utils)
    target_compile_definitions(interposer-tests PRIVATE TESTING=1)
    if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_definitions(interposer-tests PUBLIC _GNU_SOURCE=1)
    endif()
endif()
endif(INTERPOSER_BUILD_TESTS)

# =================
# Integration Tests
# =================

if(INTERPOSER_BUILD_TESTS)
    add_subdirectory(integration)
endif()

# =========
# Packaging
# =========

set(CPACK_DEBIAN_PACKAGE_NAME "scion-interposer")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_CURRENT_SOURCE_DIR}/install/debian/conffiles"
)
scion_rpm_conffiles(CPACK_RPM_USER_FILELIST
    "${CMAKE_CURRENT_SOURCE_DIR}/install/debian/conffiles"
)

set(CONCAT CPACK_DEBIAN_PACKAGE_RECOMMENDS
    "scion-daemon"
    "scion2ip"
)
set(CONCAT CPACK_DEBIAN_PACKAGE_SUGGESTS
    "scion-daemon"
    "scion2ip"
)

scion_configure_cpack(COMPONENTS INTERPOSER)
