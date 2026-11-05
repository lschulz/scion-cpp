# Default compiler settings shared by all projects in this repository.

include_guard(GLOBAL)

set(MARCH "native" CACHE STRING
    "GCC/Clang: Target machine type. An empty string does not set -march at all.")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    # Disabled warnings:
    # C4146 - unary minus operator applied to unsigned type, result still unsigned
    add_compile_options(/W3 /wd4146)
    add_compile_options(/arch:AVX2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    if(MARCH)
        add_compile_options(-march=${MARCH})
    endif()
endif()

if(WIN32)
    add_compile_definitions(
        _WIN32_WINNT=0x0A00
        NOMINMAX
    )
endif()
