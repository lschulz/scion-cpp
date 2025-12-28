# CPack settings for Debian packages

set(CPACK_PACKAGE_CHECKSUM SHA256)
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Lars-Christian Schulz <lschulz@ovgu.de>")
set(CPACK_DEBIAN_PACKAGE_DEBUG ON)

# scion++-dev
set(CPACK_DEBIAN_SCION_CPP_DEV_PACKAGE_NAME "scion++-dev")
set(CPACK_DEBIAN_SCION_CPP_DEV_DESCRIPTION
    "C++ SCION SDK"
)
string(CONCAT CPACK_DEBIAN_SCION_CPP_DEV_PACKAGE_DEPENDS
    "libboost-dev (>= 1.83.0.1ubuntu2), "
    "libboost-json-dev (>= 1.83.0.1ubuntu2), "
    "libc-ares-dev (>= 1.27.0-1.0ubuntu1), "
    "libgrpc++-dev (>= 1.51.1-4.1build5), "
    "libprotobuf-dev (>= 3.21.12-8.2ubuntu0.2)"
)

# scionc-dev
set(CPACK_DEBIAN_SCIONC_DEV_PACKAGE_NAME "scionc-dev")
set(CPACK_DEBIAN_SCIONC_DEV_DESCRIPTION
    "SCION C++ SDK C interface headers"
)
set(CPACK_DEBIAN_SCIONC_DEV_PACKAGE_DEPENDS
    "scion++-dev (= 0.0.1-1)"
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
set(CPACK_DEBIAN_INTERPOSER_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_INTERPOSER_PACKAGE_RECOMMENDS
    "scion-daemon"
)
set(CPACK_DEBIAN_INTERPOSER_PACKAGE_RECOMMENDS
    "scion++-tools"
)
endif(LINUX)

include(CPack)
