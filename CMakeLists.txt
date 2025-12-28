cmake_minimum_required(VERSION 3.28)

project(scion-cpp
    LANGUAGES C CXX
    VERSION 0.0.1
    HOMEPAGE_URL "https://github.com/lschulz/scion-cpp"
)

set(MARCH "native" CACHE STRING "GCC/Clang: Target machine type. Set to an empty string to not set -march.")
set(RELEASE NO CACHE BOOL "Build a release version")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Disabled warnings:
    # C4146 - unary minus operator applied to unsigned type, result still unsigned
    add_compile_options(/W3 /wd4146)
    add_compile_options(/arch:AVX2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wno-unused-parameter)
    add_compile_options(-fPIC)
if (MARCH)
    add_compile_options(-march=${MARCH})
endif()
endif()

if (WIN32)
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    NOMINMAX
)
endif()

include(GNUInstallDirs)

if (RELEASE)
    set(VERSION_TAG "")
else()
    # If not building for a release, add the Git commit hash to version strings.
    # The commit hash is only updated when the project is reconfigured.
    find_package(Git)
    if (GIT_EXECUTABLE)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" describe --abbrev=10 --always --match "" --dirty
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE GIT_COMMIT_HASH
            RESULT_VARIABLE GIT_RESULT
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if (NOT GIT_RESULT)
        set(VERSION_TAG "-${GIT_COMMIT_HASH}")
    else()
        set(VERSION_TAG "-dirty")
    endif()
endif()

# =====
# Boost
# =====

find_package(Boost CONFIG REQUIRED COMPONENTS json)

# ==============
# Protobuf, gRPC
# ==============

find_package(protobuf CONFIG)

# Assume protobuf has been found even if Protobuf_FOUND is false when building
# on Windows. FindProtobuf.cmake sets Protobuf_FOUND to false even if protobuf
# works.
if (Protobuf_FOUND OR WIN32)

    set(GRPC_LIBS protobuf::libprotobuf)

else()

    find_package(PkgConfig)
    pkg_check_modules(protobuf REQUIRED IMPORTED_TARGET protobuf)

    add_Executable(protobuf::protoc IMPORTED)
    find_program(PROTOC_EXECUTABLE protoc)
    set_target_properties(protobuf::protoc PROPERTIES
        IMPORTED_LOCATION "${PROTOC_EXECUTABLE}")

    set(GRPC_LIBS PkgConfig::protobuf)

endif()

find_package(grpc CONFIG)

if (gRPC_FOUND)

    list(APPEND GRPC_LIBS gRPC::grpc gRPC::grpc++)

else()

    find_package(PkgConfig)
    pkg_check_modules(grpc++ REQUIRED IMPORTED_TARGET grpc++)
    pkg_check_modules(grpc REQUIRED IMPORTED_TARGET grpc)

    add_executable(gRPC::grpc_cpp_plugin IMPORTED)
    find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
    set_target_properties(gRPC::grpc_cpp_plugin PROPERTIES
        IMPORTED_LOCATION "${GRPC_CPP_PLUGIN_EXECUTABLE}")

    list(APPEND GRPC_LIBS PkgConfig::grpc PkgConfig::grpc++)

endif()

# =========
# asio-grpc
# =========

add_subdirectory(deps/asio-grpc)

# Install a private copy of asio-grpc
install(DIRECTORY "deps/asio-grpc/src/agrpc"
    COMPONENT SCION_CPP_DEV
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/scion"
    FILES_MATCHING PATTERN "*.hpp"
)

# =====
# CLI11
# =====

add_subdirectory(deps/CLI11)

# =====
# ImTui
# =====

if (LINUX)
add_subdirectory(deps/imtui)
target_compile_options(imtui PRIVATE
    -Wno-conversion
)
target_compile_options(imtui-ncurses PRIVATE
    -Wno-conversion
)
target_compile_options(imgui-for-imtui PRIVATE
    -Wno-unused-variable
    -Wno-deprecated-enum-enum-conversion
    -Wno-conversion
)
endif(LINUX)

# ======
# spdlog
# ======

set(SPDLOG_USE_STD_FORMAT ON)
add_subdirectory(deps/spdlog)

# ==========
# GoogleTest
# ==========

include(GoogleTest)
set(INSTALL_GTEST OFF)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory(deps/googletest)

# ==============================
# Generate code from proto files
# ==============================

set(PROTO_SRC
    proto/daemon/v1/daemon.proto
    proto/drkey/v1/drkey.proto
)

add_library(scion-proto OBJECT ${PROTO_SRC})
target_link_libraries(scion-proto PUBLIC ${GRPC_LIBS})

asio_grpc_protobuf_generate(
    GENERATE_GRPC
    TARGET scion-proto
    USAGE_REQUIREMENT PUBLIC
    IMPORT_DIRS "${CMAKE_CURRENT_SOURCE_DIR}"
    OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/scion"
    PROTOS "${PROTO_SRC}"
)

# ============
# Main Library
# ============

add_library(scion-cpp STATIC)
target_sources(scion-cpp
    PRIVATE
        "src/addr/endpoint.cpp"
        "src/addr/generic_ip.cpp"
        "src/addr/isd_asn.cpp"
        "src/bit_stream.cpp"
        "src/daemon/client.cpp"
        "src/default_address.cpp"
        "src/error_codes.cpp"
        "src/hdr/details.cpp"
        "src/murmur_hash3.cpp"
        "src/path/path_meta.cpp"
        "src/path/path.cpp"
        "src/path/policy.cpp"
        "src/resolver.cpp"
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS
        "include"
        "${CMAKE_CURRENT_BINARY_DIR}/generated"
    FILES
        "include/scion/addr/address.hpp"
        "include/scion/addr/endpoint.hpp"
        "include/scion/addr/generic_ip.hpp"
        "include/scion/addr/isd_asn.hpp"
        "include/scion/addr/mapping.hpp"
        "include/scion/as_interface.hpp"
        "include/scion/asio/addresses.hpp"
        "include/scion/asio/scmp_socket.hpp"
        "include/scion/asio/udp_socket.hpp"
        "include/scion/bit_stream.hpp"
        "include/scion/daemon/client.hpp"
        "include/scion/daemon/co_client.hpp"
        "include/scion/details/bit.hpp"
        "include/scion/details/c_interface.hpp"
        "include/scion/details/debug.hpp"
        "include/scion/details/flags.hpp"
        "include/scion/details/from_chars.hpp"
        "include/scion/details/protobuf_time.hpp"
        "include/scion/drkey/drkey.hpp"
        "include/scion/error_codes.hpp"
        "include/scion/extensions/extension.hpp"
        "include/scion/extensions/idint.hpp"
        "include/scion/hdr/details.hpp"
        "include/scion/hdr/ethernet.hpp"
        "include/scion/hdr/idint.hpp"
        "include/scion/hdr/ip.hpp"
        "include/scion/hdr/proto.hpp"
        "include/scion/hdr/scion.hpp"
        "include/scion/hdr/scmp.hpp"
        "include/scion/hdr/stun.hpp"
        "include/scion/hdr/tcp.hpp"
        "include/scion/hdr/udp.hpp"
        "include/scion/murmur_hash3.h"
        "include/scion/path/attributes.hpp"
        "include/scion/path/cache.hpp"
        "include/scion/path/decoded_scion.hpp"
        "include/scion/path/digest.hpp"
        "include/scion/path/path_meta.hpp"
        "include/scion/path/path.hpp"
        "include/scion/path/policy.hpp"
        "include/scion/path/raw_hop_range.hpp"
        "include/scion/path/raw.hpp"
        "include/scion/path/shared_cache.hpp"
        "include/scion/posix/scmp_socket.hpp"
        "include/scion/posix/sockaddr.hpp"
        "include/scion/posix/udp_socket.hpp"
        "include/scion/posix/underlay.hpp"
        "include/scion/resolver.hpp"
        "include/scion/scion_asio.hpp"
        "include/scion/scion.hpp"
        "include/scion/scmp/handler.hpp"
        "include/scion/scmp/path_mtu.hpp"
        "include/scion/socket/flags.hpp"
        "include/scion/socket/header_cache.hpp"
        "include/scion/socket/packager.hpp"
        "include/scion/socket/parsed_packet.hpp"
        "${CMAKE_CURRENT_BINARY_DIR}/generated/scion/proto/daemon/v1/daemon.grpc.pb.h"
        "${CMAKE_CURRENT_BINARY_DIR}/generated/scion/proto/daemon/v1/daemon.pb.h"
        "${CMAKE_CURRENT_BINARY_DIR}/generated/scion/proto/drkey/v1/drkey.grpc.pb.h"
        "${CMAKE_CURRENT_BINARY_DIR}/generated/scion/proto/drkey/v1/drkey.pb.h"
)
target_link_libraries(scion-cpp PUBLIC
    Boost::headers
    Boost::json
    asio-grpc::asio-grpc
    scion-proto
)
target_include_directories(scion-cpp PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/asio-grpc/src"
)
set_target_properties(scion-cpp PROPERTIES
    OUTPUT_NAME "scion++"
    DEBUG_POSTFIX "d"
    VERSION "0.0.1"
    SOVERSION "0"
)
install(TARGETS scion-cpp
    COMPONENT SCION_CPP_DEV
    FILE_SET public_headers
    ARCHIVE
)

# ===========
# C Interface
# ===========

add_library(scion-c-static STATIC)
target_sources(scion-c-static
    PRIVATE
        "src/scion_c/scion.cpp"
        "src/scion_c/scion.c"
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS
        "include"
    FILES
        "include/scion/scion.h"
)
target_link_libraries(scion-c-static PRIVATE scion-cpp)
set_target_properties(scion-c-static PROPERTIES
    OUTPUT_NAME "scionc"
    DEBUG_POSTFIX "d"
)
install(TARGETS scion-c-static
    COMPONENT SCIONC_DEV
    FILE_SET public_headers
    ARCHIVE
)

add_library(scion-c SHARED)
target_sources(scion-c
    PRIVATE
        "src/scion_c/scion.cpp"
        "src/scion_c/scion.c"
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS
        "include"
    FILES
        "include/scion/scion.h"
)
target_link_libraries(scion-c PRIVATE scion-cpp)
if (WIN32)
    target_link_libraries(scion-c INTERFACE Ws2_32.lib)
endif()
set_target_properties(scion-c PROPERTIES
    OUTPUT_NAME "scionc"
    # Rename import library file on DLL platforms (Windows) to avoid name
    # conflict with static library.
    ARCHIVE_OUTPUT_NAME "scionc-import"
    DEBUG_POSTFIX "d"
    VERSION "0.0.1"
    SOVERSION "0"
)
install(TARGETS scion-c
    COMPONENT SCIONC
    RUNTIME
)

# ==========
# Unit Tests
# ==========

enable_testing()

set(SRC_TEST
    "tests/addr/test_address.cpp"
    "tests/addr/test_endpoint.cpp"
    "tests/addr/test_generic_ip.cpp"
    "tests/addr/test_isd_asn.cpp"
    "tests/asio/test_addresses.cpp"
    "tests/asio/test_scmp_socket.cpp"
    "tests/asio/test_udp_socket.cpp"
    "tests/hdr/test_checksum.cpp"
    "tests/hdr/test_idint.cpp"
    "tests/hdr/test_ip.cpp"
    "tests/hdr/test_scion.cpp"
    "tests/hdr/test_scmp.cpp"
    "tests/hdr/test_stun.cpp"
    "tests/hdr/test_tcp.cpp"
    "tests/main.cpp"
    "tests/path/test_cache.cpp"
    "tests/path/test_decoded_scion.cpp"
    "tests/path/test_path_meta.cpp"
    "tests/path/test_path.cpp"
    "tests/path/test_policy.cpp"
    "tests/path/test_protobuf_time.cpp"
    "tests/path/test_raw_path.cpp"
    "tests/posix/test_addr.cpp"
    "tests/posix/test_scmp_socket.cpp"
    "tests/posix/test_udp_socket.cpp"
    "tests/resolver/test_resolver.cpp"
    "tests/scion_c/test_c_interface.cpp"
    "tests/scmp/test_path_mtu.cpp"
    "tests/socket/test_header_cache.cpp"
    "tests/socket/test_packager.cpp"
    "tests/socket/test_parsed_packet.cpp"
    "tests/test_bit_stream.cpp"
    "tests/utilities.cpp"
)

add_executable(unit-tests ${SRC_TEST})
target_link_libraries(unit-tests PRIVATE gtest gmock scion-cpp scion-c-static)
target_include_directories(unit-tests
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

gtest_discover_tests(unit-tests
    EXTRA_ARGS "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

# ----------
# Interposer
# ----------

if (NOT WIN32)
add_subdirectory(interposer)
endif()

# ------
# SCITRA
# ------

add_subdirectory(scitra)

# ========
# Examples
# ========

add_subdirectory(examples)

# =========
# Packaging
# =========

include(cmake/packaging_deb.cmake)
