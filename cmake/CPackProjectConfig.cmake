# This file is evaluated once per generator during CPack packaging time.
# Place per-generator settings here.

# Warn if system packages are being built with a CMAKE_INSTALL_PREFIX != "/".
if(NOT CPACK_PACKAGE_RELOCATABLE)
    if(CPACK_GENERATOR MATCHES "^(DEB|RPM)$" AND NOT CPACK_PACKAGING_INSTALL_PREFIX STREQUAL "/")
        message(WARNING "Building ${CPACK_GENERATOR} package ${CPACK_PACKAGE_NAME} with"
            " installation prefix \"${CPACK_PACKAGING_INSTALL_PREFIX}\". System packages should be"
            " built with -DCMAKE_INSTALL_PREFIX=/.")
    endif()
endif()
