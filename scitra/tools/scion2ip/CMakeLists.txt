cmake_minimum_required(VERSION 3.28)

project(scion2ip
    VERSION 0.1.0
    DESCRIPTION "SCION-mapped IPv6 address converter"
    HOMEPAGE_URL "https://github.com/lschulz/scion-cpp"
    LANGUAGES CXX
)

if(PROJECT_IS_TOP_LEVEL)
    list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/../../../cmake")
    include(CompilerOptions)
    include(VersionTag)
    include(Submodules)
    include(Packaging)
    include(GNUInstallDirs)
    find_package(scion-cpp 0.0.5 REQUIRED)
endif()

# ========
# scion2ip
# ========

configure_file("src/version.cpp.in" "version.cpp")

add_executable(scion2ip)
target_sources(scion2ip PRIVATE
    "src/scion2ip.cpp"
    "${CMAKE_CURRENT_BINARY_DIR}/version.cpp"
)
target_include_directories(scion2ip PRIVATE "${CMAKE_SOURCE_DIR}/include")
target_link_libraries(scion2ip PRIVATE CLI11::CLI11 scion::cpp)

set_target_properties(scion2ip PROPERTIES
    OUTPUT_NAME "scion2ip"
    DEBUG_POSTFIX "-d"
)
install(TARGETS scion2ip
    COMPONENT SCION2IP
    RUNTIME
)
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/man/scion2ip.1.gz"
    COMPONENT SCION2IP
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/man/man1/"
)

# =========
# Packaging
# =========

set(CPACK_DEBIAN_PACKAGE_NAME "scion2ip")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

SET(CPACK_RPM_PACKAGE_NAME "scion2ip")

scion_configure_cpack(COMPONENTS SCION2IP)
