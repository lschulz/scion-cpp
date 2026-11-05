# Functions for adding dependencies from Git submodules in deps/.
#
# These functions ensure dependencies are only added one per build regardless
# of whether the subprojects are built on their own or as part of the whole
# repository.

set(_SCION_DEPS_DIR "${CMAKE_CURRENT_LIST_DIR}/../deps")
cmake_path(NORMAL_PATH _SCION_DEPS_DIR)

# Pass optional argument SYSTEM to silence warnings from included headers.
function(_scion_add_submodule name)
    add_subdirectory("${_SCION_DEPS_DIR}/${name}" "${CMAKE_BINARY_DIR}/deps/${name}" ${ARGN})
endfunction()

# =====
# CLI11
# =====

function(scion_add_cli11)
    if(NOT TARGET CLI11::CLI11)
        _scion_add_submodule(CLI11 SYSTEM)
    endif()
endfunction()

# ======
# spdlog
# ======

function(scion_add_spdlog)
    if(NOT TARGET spdlog::spdlog)
        set(SPDLOG_USE_STD_FORMAT ON)
        _scion_add_submodule(spdlog SYSTEM)
    endif()
endfunction()

# =====
# ImTui
# =====

function(scion_add_imtui)
    if(NOT TARGET imtui)
        _scion_add_submodule(imtui SYSTEM)
        target_compile_options(imtui PRIVATE
            -Wno-conversion
        )
        target_compile_options(imtui-ncurses PRIVATE
            -Wno-conversion
        )
        target_compile_options(imgui-for-imtui PRIVATE
            -Wno-unused-variable
            -Wno-deprecated-enum-enum-conversion
            -Wno-nontrivial-memcall
            -Wno-conversion
        )
    endif()
endfunction()

# ==========
# GoogleTest
# ==========

function(scion_add_googletest)
    if(NOT TARGET gtest)
        set(INSTALL_GTEST OFF)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        _scion_add_submodule(googletest SYSTEM)
    endif()
endfunction()
