cmake_minimum_required(VERSION 3.28)

include(cmake/version.cmake)

project(scion-cpp
    LANGUAGES C CXX
    VERSION "${PROJECT_VERSION}"
    HOMEPAGE_URL "https://github.com/lschulz/scion-cpp"
)

# Cache Variables

set(MARCH "native" CACHE STRING "GCC/Clang: Target machine type. \
An empty string does not set -march at all.")

set(BOTAN_CA_BUNDLE "" CACHE STRING
"Set path to target system's trusted cert bundle. An empty string lets the \
Botan configure script detect the correct directory for the build environment.")

set(RELEASE NO CACHE BOOL "Build a release version.")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # Disabled warnings:
    # C4146 - unary minus operator applied to unsigned type, result still unsigned
    add_compile_options(/W3 /wd4146)
    add_compile_options(/arch:AVX2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wno-unused-parameter)
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

include(GNUInstallDirs)

if(RELEASE)
    set(VERSION_TAG "")
else()
    # If not building for a release, add the Git commit hash to version strings.
    # The commit hash is only updated when the project is reconfigured.
    find_package(Git)
    if(GIT_EXECUTABLE)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" describe --abbrev=10 --always --match "" --dirty
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE GIT_COMMIT_HASH
            RESULT_VARIABLE GIT_RESULT
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if(NOT GIT_RESULT)
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
if(Protobuf_FOUND OR WIN32)

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

if(gRPC_FOUND)

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

if(LINUX)
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

# =====
# Botan
# =====

find_package(Python3 REQUIRED COMPONENTS Interpreter)

# List of Botan modules to build. Keep this to the minimum required by SCION and
# TLS 1.2 and 1.3 (for SCION bootstrapping).
set(BOTAN_MODULE_LIST
    aes
    aes_ni
    asio
    auto_rng
    cbc      # for ID-INT
    certstor_flatfile
    certstor_system
    chacha20poly1305
    cmac
    ctr      # for ID-INT
    ctr_avx2 # for ID-INT
    ecdsa
    eme_pkcs1,
    emsa_pkcs1
    emsa_pssr
    gcm
    hmac_drbg
    pcurves_secp256r1
    pcurves_secp384r1
    pcurves_secp521r1
    pem
    prf_tls
    rsa
    sha2_32
    sha2_64
    system_rng
    tls12
    tls13
    x25519
    x509
)
list(JOIN BOTAN_MODULE_LIST "," BOTAN_MODULES)

set(BOTAN_DIR "${CMAKE_CURRENT_BINARY_DIR}/botan")
set(BOTAN_AMALGAMATION "${BOTAN_DIR}/botan_all.cpp")
set(BOTAN_STAMP_FILE "${BOTAN_DIR}/modules.stamp")
if (NOT EXISTS "${BOTAN_STAMP_FILE}")
    set(BOTAN_STAMP "")
else()
    file(READ "${BOTAN_STAMP_FILE}" BOTAN_STAMP)
endif()

set(BOTAN_CONFIGURE_EXTRA_ARGS)
if(BOTAN_CA_BUNDLE)
    list(APPEND BOTAN_CONFIGURE_EXTRA_ARGS "--system-crt-bundle=${BOTAN_CA_BUNDLE}")
endif()

# Re-configure Botan if the module list is out-of-date
set(BOTAN_STAMP_EXPECTED "${BOTAN_MODULES}|${BOTAN_CA_BUNDLE}")
if(NOT EXISTS "${BOTAN_AMALGAMATION}" OR NOT "${BOTAN_STAMP}" STREQUAL "${BOTAN_STAMP_EXPECTED}")
    file(MAKE_DIRECTORY "${BOTAN_DIR}")
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/deps/botan/configure.py"
            --quiet
            --amalgamation
            --minimized-build
            --build-targets=static
            --disable-shared-library
            --without-documentation
            --with-boost
            --enable-modules=${BOTAN_MODULES}
            ${BOTAN_CONFIGURE_EXTRA_ARGS}
        WORKING_DIRECTORY "${BOTAN_DIR}"
        RESULT_VARIABLE BOTAN_CONFIGURE_RESULT
    )
    if(NOT BOTAN_CONFIGURE_RESULT EQUAL 0)
        message(FATAL_ERROR "Configuring bundled Botan failed with code ${BOTAN_CONFIGURE_RESULT}")
    endif()
    file(WRITE "${BOTAN_STAMP_FILE}" "${BOTAN_STAMP_EXPECTED}")
endif()

# Link Botan as static library, consider dynamic linking later
add_library(botan STATIC "${BOTAN_AMALGAMATION}")
target_include_directories(botan SYSTEM PUBLIC "${BOTAN_DIR}/build/include/public")
target_compile_features(botan PUBLIC cxx_std_20)
set_target_properties(botan PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Disable warnings from generated Botan code
if(MSVC)
    target_compile_options(botan PRIVATE /w)
else()
    target_compile_options(botan PRIVATE -w)
endif()

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
        "src/crypto/aes.cpp"
        "src/daemon/client.cpp"
        "src/default_address.cpp"
        "src/detect_cpu.cpp"
        "src/error_codes.cpp"
        "src/extensions/idint.cpp"
        "src/hash.cpp"
        "src/hdr/details.cpp"
        "src/hdr/scmp.cpp"
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
        "include/scion/crypto/aes.hpp"
        "include/scion/daemon/client.hpp"
        "include/scion/daemon/co_client.hpp"
        "include/scion/details/bit.hpp"
        "include/scion/details/c_interface.hpp"
        "include/scion/details/debug.hpp"
        "include/scion/details/flags.hpp"
        "include/scion/details/from_chars.hpp"
        "include/scion/details/protobuf_time.hpp"
        "include/scion/detect_cpu.hpp"
        "include/scion/drkey/drkey.hpp"
        "include/scion/drkey/key_cache.hpp"
        "include/scion/error_codes.hpp"
        "include/scion/extensions/extension.hpp"
        "include/scion/extensions/idint_instr.hpp"
        "include/scion/extensions/idint_path_helper.hpp"
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
target_link_libraries(scion-cpp PRIVATE
    botan
)
target_include_directories(scion-cpp PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/asio-grpc/src"
)
set_target_properties(scion-cpp PROPERTIES
    OUTPUT_NAME "scion++"
    DEBUG_POSTFIX "d"
    VERSION "${SCION_CPP_VERSION}"
    SOVERSION "${SCION_CPP_SO_VERSION}"
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
if(WIN32)
    target_link_libraries(scion-c INTERFACE Ws2_32.lib)
endif()
set_target_properties(scion-c PROPERTIES
    OUTPUT_NAME "scionc"
    # Rename import library file on DLL platforms (Windows) to avoid name
    # conflict with static library.
    ARCHIVE_OUTPUT_NAME "scionc-import"
    DEBUG_POSTFIX "d"
    VERSION "${SCION_C_VERSION}"
    SOVERSION "${SCION_C_SO_VERSION}"
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
    "tests/crypto/test_aes.cpp"
    "tests/drkey/test_key_cache.cpp"
    "tests/extensions/test_idint_api.cpp"
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

if(NOT WIN32)
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
