# Detect dependency versions for deb and rpm packages.

find_program(DPKG_QUERY dpkg-query)
find_program(RPM_BINARY rpm)

function(get_pkg_versions format out)

    list(REMOVE_DUPLICATES ARGN)

    set(deps "")
    if(format STREQUAL "deb")
        if(NOT DPKG_QUERY)
            message(FATAL_ERROR "dpkg-query not found")
        endif()
        foreach(pkg IN LISTS ARGN)
            execute_process(
                COMMAND ${DPKG_QUERY} --show "-f=\${Version}" ${pkg}
                OUTPUT_VARIABLE ver
                RESULT_VARIABLE res)
            list(APPEND deps "${pkg} >= (${ver})")
        endforeach()
    elseif(format STREQUAL "rpm")
        if(NOT RPM_BINARY)
            message(FATAL_ERROR "rpm not found")
        endif()
        foreach(pkg IN LISTS ARGN)
            execute_process(
                COMMAND ${RPM_BINARY} --query --qf "%{EVR}" ${pkg}
                OUTPUT_VARIABLE ver
                RESULT_VARIABLE res)
            list(APPEND deps "${pkg} >= ${ver}")
        endforeach()
    else()
        message(FATAL_ERROR "unknown package format")
    endif()

    list(JOIN deps ", " joined)
    set({$out} "${joined}" PARENT_SCOPE)

endfunction()
