cmake_minimum_required(VERSION 3.28)

# ============
# Dependencies
# ============

find_package(re2 CONFIG)

if (re2_FOUND)
    set(RE2 re2::re2)
else()
    find_package(PkgConfig)
    pkg_check_modules(re2 REQUIRED IMPORTED_TARGET re2)
    set(RE2 PkgConfig::re2)
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
target_link_libraries(interposer PRIVATE scion-cpp scion-c-static ${RE2})
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
    VERSION "0.0.2"
    SOVERSION "0"
)
install(TARGETS interposer
    COMPONENT INTERPOSER
    RUNTIME
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/install/interposer.toml"
    COMPONENT INTERPOSER
    # Only install to an absolute path if CPACK_SET_DESTDIR is requested explicitly.
    DESTINATION $<IF:$<BOOL:${CPACK_SET_DESTDIR}>,/etc/scion/,${CMAKE_INSTALL_SYSCONFDIR}/scion/>
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
target_link_libraries(default-selector PRIVATE scion-c)
set_target_properties(default-selector PROPERTIES
    PREFIX ""
)

# ==========
# Unit Tests
# ==========

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
target_link_libraries(interposer-tests PRIVATE gtest gmock scion-cpp scion-c)
target_compile_definitions(interposer-tests PRIVATE TESTING=1)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_definitions(interposer-tests PUBLIC _GNU_SOURCE=1)
endif()

# =================
# Integration Tests
# =================

add_subdirectory(integration)
