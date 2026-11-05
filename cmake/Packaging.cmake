# Helpers for CPack packaging

set(SCION_PACKAGE_MAINTAINER "Lars-Christian Schulz <lars@lcschulz.de>")
set(SCION_PACKAGE_LICENSE "MIT")
set(SCION_PACKAGE_RELEASE 1)

# Determine package format of the build host
cmake_host_system_information(RESULT SCION_OS QUERY DISTRIB_INFO)
if(SCION_OS_ID STREQUAL "debian" OR SCION_OS_ID_LIKE MATCHES "debian")
    set(SCION_PACKAGE_FORMAT "deb")
elseif(SCION_OS_ID STREQUAL "fedora" OR SCION_OS_ID_LIKE MATCHES "fedora")
    set(SCION_PACKAGE_FORMAT "rpm")
else()
    set(SCION_PACKAGE_FORMAT "")
endif()

# Record the directory this file and CPackProjectConfig.cmake are in for setting
# CPACK_PROJECT_CONFIG_FILE in scion_configure_cpack.
set(_MY_CMAKE_LIST_DIR "${CMAKE_CURRENT_LIST_DIR}")

# scion_configure_cpack([RELOCATABLE] COMPONENTS <component>...)
#
# Generates a CPack configuration for the given components of the top-level
# project. The package name, version, and description are taken from the last
# project() declaration instead of the top-level project. This allows for
# independent packaging of subprojects.
#
# Set RELOCATABLE if the package does not contain files at absolute paths (e.g.
# /etc/scion). If the project has multiple installation components, specify them
# after COMPONENTS and set the per-component configuration variables before
# calling this function.
function(scion_configure_cpack)
    cmake_parse_arguments(PARSE_ARGV 0 ARG "RELOCATABLE" "" "COMPONENTS")
    if(NOT ARG_COMPONENTS)
        message(FATLA_ERROR "scion_configure_cpack: COMPONENTS is required")
    endif()

    # Set CPack variables to values from the most recent project() call
    set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
    set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
    set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
    set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
    set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
    set(CPACK_PACKAGE_DESCRIPTION "${PROJECT_DESCRIPTION}")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
    set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")
    set(CPACK_PACKAGE_CHECKSUM SHA256)
    set(CPACK_PACKAGE_RELOCATABLE ${ARG_RELOCATABLE})
    set(CPACK_PROJECT_CONFIG_FILE "${_MY_CMAKE_LIST_DIR}/CPackProjectConfig.cmake")

    # Output CPack configuration to per-subproject locations
    set(CPACK_OUTPUT_CONFIG_FILE "${PROJECT_BINARY_DIR}/CPackConfig.cmake")
    set(CPACK_SOURCE_OUTPUT_CONFIG_FILE "${PROJECT_BINARY_DIR}/CPackSourceConfig.cmake")

    # Use the same install prefix for manual installation and packaging.
    # The DEB and RPM generators otherwise use /usr which places configuration
    # files into /usr/etc/ instead of /etc if CMAKE_INSTALL_PREFIX=/.
    set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

    # DEB
    set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
    set(CPACK_DEBIAN_PACKAGE_RELEASE "${SCION_PACKAGE_RELEASE}")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${SCION_PACKAGE_MAINTAINER}")

    # RPM
    set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
    set(CPACK_RPM_PACKAGE_RELEASE "${SCION_PACKAGE_RELEASE}")
    set(CPACK_RPM_PACKAGE_LICENSE "${SCION_PACKAGE_LICENSE}")

    list(LENGTH ARG_COMPONENTS count)
    if(count EQUAL 1)
        set(CPACK_INSTALL_CMAKE_PROJECTS
            "${PROJECT_BINARY_DIR};${PROJECT_NAME};${ARG_COMPONENTS};/")
        set(CPACK_DEB_COMPONENT_INSTALL OFF)
        set(CPACK_RPM_COMPONENT_INSTALL OFF)
    else()
        set(CPACK_INSTALL_CMAKE_PROJECTS "${PROJECT_BINARY_DIR};${PROJECT_NAME};ALL;/")
        set(CPACK_COMPONENTS_ALL ${ARG_COMPONENTS})
        set(CPACK_DEB_COMPONENT_INSTALL ON)
        set(CPACK_RPM_COMPONENT_INSTALL ON)
    endif()

    # Include at function scope, so different configurations stay separate
    include(CPack)
endfunction()

# scion_get_dep_versions(<deb|rpm> <out-var>
#                        [SAME_MAJOR <package>...]
#                        [SAME_MINOR <package>...])
#
# Builds a dependency list of the given system packages with the package
# versions installed on the build host. Packages are constrained to at least the
# version on the build host. Packages under SAME_MAJOR are additionally
# constrained to the same major version. Packages under SAME_MINOR are
# constrained to the same major in minor version.
function(scion_get_dep_versions format out)
    cmake_parse_arguments(PARSE_ARGV 2 ARG "" "" "SAME_MAJOR;SAME_MINOR")
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "scion_get_dep_versions: packages must be listed"
            " after SAME_MAJOR or SAME_MINOR")
    endif()

    if(format STREQUAL "deb")
        find_program(DPKG_QUERY dpkg-query REQUIRED)
    elseif(format STREQUAL "rpm")
        find_program(RPM_BINARY rpm REQUIRED)
    else()
        message(FATAL_ERROR "scion_get_dep_versions: unknown package format ${format}")
    endif()

    set(deps "")
    foreach(level IN ITEMS MAJOR MINOR)
        foreach(pkg IN LISTS ARG_SAME_${level})
            _scion_get_dep_versions(${format} ${level} ${pkg} dep)
            list(APPEND deps ${dep})
        endforeach()
    endforeach()

    list(JOIN deps ", " joined)
    set(${out} "${joined}" PARENT_SCOPE)
endfunction()

function(_scion_get_dep_versions format level pkg out)
    if(format STREQUAL "deb")
        execute_process(
            COMMAND ${DPKG_QUERY} --show "-f=\${Version}" ${pkg}
            OUTPUT_VARIABLE ver
            RESULT_VARIABLE res)
    else()
        execute_process(
            COMMAND ${RPM_BINARY} --query --qf "%{EVR}" ${pkg}
            OUTPUT_VARIABLE ver
            RESULT_VARIABLE res)
    endif()
    if(NOT res EQUAL 0 OR NOT ver)
        message(WARNING "Package ${pkg} is not installed, adding dependency without version.")
        set(${out} "${pkg}" PARENT_SCOPE)
        return()
    endif()

    # Lower bound: exact version
    if(format STREQUAL "deb")
        set(lower "(>= ${ver})")
    else()
        set(lower ">= ${ver}")
    endif()

    # Upper bound: next major or minor version
    set(upper "")
    if(level STREQUAL "MINOR" AND ver MATCHES "^(([0-9]+):)?([0-9]+)\\.([0-9]+)")
        math(EXPR next "${CMAKE_MATCH_4} + 1")
        set(upper "${CMAKE_MATCH_3}.${next}~")
    elseif(level STREQUAL "MAJOR" AND ver MATCHES "^(([0-9]+):)?([0-9]+)")
        math(EXPR next "${CMAKE_MATCH_3} + 1")
        set(upper "${next}~")
    endif()
    if(upper)
        if (CMAKE_MATCH_1)
            # keep same epoch
            set(upper "${CMAKE_MATCH_2}:${upper}")
        endif()
        if(format STREQUAL "deb")
            set(upper "(<< ${upper})")
        else()
            set(upper "< ${upper}")
        endif()
    else()
        message(WARNING "Cannot determine ${level} version of ${pkg} ${ver},"
            " adding without upper bound")
    endif()

    set(${out} "${pkg} ${lower} ${upper}" PARENT_SCOPE)
endfunction()

# scion_rpm_conffiles(<out-var> <path to conffiles>)
#
# Reads a Debian-style conffiles control file and converts it to a list of
# %config(noreplace) directives.
function(scion_rpm_conffiles out conffiles)
    file(STRINGS "${conffiles}" files REGEX "^/")
    # reconfigure if conffiles changes
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${conffiles}")

    set(filelist "")
    foreach(file IN LISTS files)
        list(APPEND filelist "%config(noreplace) ${file}")
    endforeach()

    set(${out} ${filelist} PARENT_SCOPE)
endfunction()
