# CPack settings for Debian packages

set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Lars-Christian Schulz <lars@lcschulz.de>")
set(CPACK_DEBIAN_PACKAGE_DEBUG ON)

# scion++-dev
set(CPACK_DEBIAN_SCION_CPP_DEV_PACKAGE_NAME "scion++-dev")
set(CPACK_DEBIAN_SCION_CPP_DEV_DESCRIPTION
    "C++ SCION SDK"
)
# package names for Ubuntu
get_pkg_versions(deb DEB_SCION_CPP_DEPS
    libboost-dev
    libboost-json-dev
    libc-ares-dev
    libgrpc++-dev
    libprotobuf-dev
)
set(CPACK_DEBIAN_SCION_CPP_DEV_PACKAGE_DEPENDS "${DEB_SCION_CPP_DEPS}")

# scionc-dev
set(CPACK_DEBIAN_SCIONC_DEV_PACKAGE_NAME "scionc-dev")
set(CPACK_DEBIAN_SCIONC_DEV_DESCRIPTION
    "SCION C++ SDK C interface headers"
)
set(CPACK_DEBIAN_SCIONC_DEV_PACKAGE_DEPENDS
    "scion++-dev (= ${SCION_CPP_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE})"
)

# scionc
set(CPACK_DEBIAN_SCIONC_PACKAGE_NAME "scionc")
set(CPACK_DEBIAN_SCIONC_DESCRIPTION
    "SCION C++ SDK C runtime files"
)

# scion++-tools
set(CPACK_DEBIAN_TOOLS_PACKAGE_NAME "scion++-tools")
set(CPACK_DEBIAN_TOOLS_DESCRIPTION
    "CLI tools for users of applications produced with the SCION C++ SDK"
)
set(CPACK_DEBIAN_TOOLS_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_TOOLS_PACKAGE_SHLIBDEPS ON)

# scitra-tun
if (LINUX)
set(CPACK_DEBIAN_SCITRA_TUN_PACKAGE_NAME "scitra-tun")
set(CPACK_DEBIAN_SCITRA_TUN_DESCRIPTION
    "Userspace SCION-IP Translator for Linux"
)
set(CPACK_DEBIAN_SCITRA_TUN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_SCITRA_TUN_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/scitra/install/scitra-tun/debian/conffiles"
)
set(CPACK_DEBIAN_SCITRA_TUN_PACKAGE_SHLIBDEPS ON)
string(CONCAT CPACK_DEBIAN_SCITRA_TUN_PACKAGE_RECOMMENDS
    "scion-daemon, "
    "scion++-tools"
)
endif(LINUX)

# scion-interposer
if (LINUX)
set(CPACK_DEBIAN_INTERPOSER_PACKAGE_NAME "scion-interposer")
set(CPACK_DEBIAN_INTERPOSER_DESCRIPTION
    "Emulates native SCION support in applications that use libc for network I/O"
)
set(CPACK_DEBIAN_INTERPOSER_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_INTERPOSER_PACKAGE_CONTROL_EXTRA
    "${CMAKE_SOURCE_DIR}/interposer/install/debian/conffiles"
)
set(CPACK_DEBIAN_INTERPOSER_PACKAGE_SHLIBDEPS ON)
set(CONCAT CPACK_DEBIAN_INTERPOSER_PACKAGE_RECOMMENDS
    "scion-daemon"
    "scion++-tools"
)
endif(LINUX)
