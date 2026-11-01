# CPack settings for RPM packages

set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_RPM_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_DEBUG ON)

# Function that reads a Debian-style conffiles control file and applies it as
# %config(noreplace) directives to an RPM package.
function(cpack_rpm_conffiles component conffiles)

    file(STRINGS "${conffiles}" files REGEX "^/")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${conffiles}")

    set(filelist "")
    foreach(file IN LISTS files)
        list(APPEND filelist "%config(noreplace) ${file}")
    endforeach()

    set(CPACK_RPM_${component}_USER_FILELIST ${SCITRA_RPM_FILELIST} PARENT_SCOPE)

endfunction()

# scion++-dev
set(CPACK_RPM_SCION_CPP_DEV_PACKAGE_NAME "scion++-devel")
set(CPACK_RPM_SCION_CPP_DEV_DESCRIPTION
    "C++ SCION SDK"
)
# package names for Fedora
get_pkg_versions(rpm RPM_SCION_CPP_DEPS
    boost-devel
    c-ares-devel
    grpc-devel
    protobuf-devel
)
set(CPACK_RPM_SCION_CPP_DEV_PACKAGE_REQUIRES "${RPM_SCION_CPP_DEPS}")

# scionc-dev
set(CPACK_RPM_SCIONC_DEV_PACKAGE_NAME "scionc-devel")
set(CPACK_RPM_SCIONC_DEV_DESCRIPTION
    "SCION C++ SDK C interface headers"
)
set(CPACK_RPM_SCIONC_DEV_PACKAGE_REQUIRES
    "scion++-dev = ${SCION_CPP_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}"
)

# scionc
set(CPACK_RPM_SCIONC_PACKAGE_NAME "scionc")
set(CPACK_RPM_SCIONC_DESCRIPTION
    "SCION C++ SDK C runtime files"
)

# scion++-tools
set(CPACK_RPM_TOOLS_PACKAGE_NAME "scion++-tools")
set(CPACK_RPM_TOOLS_DESCRIPTION
    "CLI tools for users of applications produced with the SCION C++ SDK"
)

# scitra-tun
if (LINUX)
set(CPACK_RPM_SCITRA_TUN_PACKAGE_NAME "scitra-tun")
set(CPACK_RPM_SCITRA_TUN_DESCRIPTION
    "Userspace SCION-IP Translator for Linux"
)
cpack_rpm_conffiles(SCITRA_TUN
    "${CMAKE_SOURCE_DIR}/scitra/install/scitra-tun/debian/conffiles")
string(CONCAT CPACK_RPM_SCITRA_TUN_PACKAGE_SUGGESTS
    "scion-daemon, "
    "scion++-tools"
)
endif(LINUX)

# scion-interposer
if (LINUX)
set(CPACK_RPM_INTERPOSER_PACKAGE_NAME "scion-interposer")
set(CPACK_RPM_INTERPOSER_DESCRIPTION
    "Emulates native SCION support in applications that use libc for network I/O"
)
cpack_rpm_conffiles(INTERPOSER
    "${CMAKE_SOURCE_DIR}/interposer/install/debian/conffiles"
)
set(CONCAT CPACK_DEBIAN_INTERPOSER_PACKAGE_SUGGESTS
    "scion-daemon"
    "scion++-tools"
)
endif(LINUX)
