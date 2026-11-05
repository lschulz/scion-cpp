# Set VERSION_TAG
#
# VERSION_TAG contains the Git commit hash if not building for a release,
# otherwise it is empty. The commit hash is only updated when the project is
# reconfigured.

set(RELEASE NO CACHE BOOL "Build a release version")

if(RELEASE)
    set(VERSION_TAG "")
else()
    find_package(Git QUIET)
    set(GIT_RESULT 1)
    if(GIT_EXECUTABLE)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" describe --abbrev=10 --always --match "" --dirty
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE GIT_COMMIT_HASH
            RESULT_VARIABLE GIT_RESULT
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if(GIT_RESULT EQUAL 0)
        set(VERSION_TAG "-${GIT_COMMIT_HASH}")
    else()
        set(VERSION_TAG "-dirty")
    endif()
endif()
