cmake_minimum_required(VERSION 3.28)

project(scion-cpp
    VERSION 0.0.5
    DESCRIPTION "SCION SDK for C++"
    HOMEPAGE_URL "https://github.com/lschulz/scion-cpp"
    LANGUAGES C CXX
)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# =============
# Build Options
# =============

option(SCION_CPP_BUILD_TESTS "Build the unit tests" ${PROJECT_IS_TOP_LEVEL})
option(SCION_CPP_BUILD_EXAMPLES "Build the examples" ${PROJECT_IS_TOP_LEVEL})
option(SCION_CPP_BUILD_APPS "Build the included applications" ${PROJECT_IS_TOP_LEVEL})

set(BOTAN_CA_BUNDLE "" CACHE STRING
"Set path to target system's trusted cert bundle. An empty string lets the \
Botan configure script detect the correct directory for the build environment.")

include(CompilerOptions)
include(VersionTag)
include(Submodules)
include(Packaging)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

# =====================
# External Dependencies
# =====================

# Boost, Protobuf, gRPC
include(scion-cpp-dependencies)

# (Build-only) Protobuf compiler
if(NOT TARGET protobuf::protoc)
    find_program(PROTOC_EXECUTABLE protoc REQUIRED)
    add_executable(protobuf::protoc IMPORTED)
    set_target_properties(protobuf::protoc PROPERTIES
        IMPORTED_LOCATION "${PROTOC_EXECUTABLE}")
endif()

# (Build-only) Protobuf compiler gRPC plugin
if(NOT TARGET gRPC::grpc_cpp_plugin)
    find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)
    add_executable(gRPC::grpc_cpp_plugin IMPORTED)
    set_target_properties(gRPC::grpc_cpp_plugin PROPERTIES
        IMPORTED_LOCATION "${GRPC_CPP_PLUGIN_EXECUTABLE}")
endif()

# =========
# asio-grpc
# =========

add_subdirectory(deps/asio-grpc) # provides asio_grpc_protobuf_generate()

# Install a private copy of asio-grpc alongside the scion-cpp headers. The
# target scion_agrpc replaces asio-grpc::asio-grpc so that exported targets
# refer to the private copy.
add_library(scion_agrpc INTERFACE)
add_library(scion::agrpc ALIAS scion_agrpc)
target_include_directories(scion_agrpc SYSTEM INTERFACE
    "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/deps/asio-grpc/src>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/scion>"
)

target_compile_definitions(scion_agrpc INTERFACE AGRPC_BOOST_ASIO)
target_compile_features(scion_agrpc INTERFACE cxx_std_17)
set_target_properties(scion_agrpc PROPERTIES
    EXPORT_NAME "agrpc"
)

install(TARGETS scion_agrpc
    COMPONENT SCION_CPP_DEV
    EXPORT scion-cpp-targets
)
install(DIRECTORY "deps/asio-grpc/src/agrpc"
    COMPONENT SCION_CPP_DEV
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/scion"
    FILES_MATCHING PATTERN "*.hpp"
)

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
    list(APPEND BOTAN_CONFIGURE_EXTRA_ARGS "--system-cert-bundle=${BOTAN_CA_BUNDLE}")
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

add_library(botan OBJECT "${BOTAN_AMALGAMATION}")
target_include_directories(botan SYSTEM PUBLIC "${BOTAN_DIR}/build/include/public")
target_link_libraries(botan PUBLIC Boost::headers)
target_compile_features(botan PUBLIC cxx_std_20)
set_target_properties(botan PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Disable warnings from generated Botan code
target_compile_options(botan PRIVATE -w)

# The Botan amalgamation results in an object file with many sections which
# requires compiling with /bigobj.
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(botan PRIVATE /bigobj)
endif()

# ==============================
# Generate code from proto files
# ==============================

set(PROTO_SRC
    proto/daemon/v1/daemon.proto
    proto/drkey/v1/drkey.proto
)

add_library(scion-proto OBJECT ${PROTO_SRC})
target_link_libraries(scion-proto PUBLIC
    protobuf::libprotobuf gRPC::grpc gRPC::grpc++)

asio_grpc_protobuf_generate(
    GENERATE_GRPC
    TARGET scion-proto
    USAGE_REQUIREMENT PUBLIC
    IMPORT_DIRS "${PROJECT_SOURCE_DIR}"
    OUT_DIR "${PROJECT_BINARY_DIR}/generated/scion"
    PROTOS "${PROTO_SRC}"
)

# Silence warning from generated header files
set_target_properties(scion-proto PROPERTIES SYSTEM ON)

# Silence warnings from compiling generated source files
target_compile_options(scion-proto PRIVATE -w)

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
        "${PROJECT_BINARY_DIR}/generated"
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
        "include/scion/hash.hpp"
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
        "${PROJECT_BINARY_DIR}/generated/scion/proto/daemon/v1/daemon.grpc.pb.h"
        "${PROJECT_BINARY_DIR}/generated/scion/proto/daemon/v1/daemon.pb.h"
        "${PROJECT_BINARY_DIR}/generated/scion/proto/drkey/v1/drkey.grpc.pb.h"
        "${PROJECT_BINARY_DIR}/generated/scion/proto/drkey/v1/drkey.pb.h"
)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|x64|AMD64")
    target_sources(scion-cpp PRIVATE "src/crypto/aes_avx2.cpp")
    if (NOT MSVC)
        set_source_files_properties("src/crypto/aes_avx2.cpp"
            PROPERTIES COMPILE_OPTIONS "-maes;-mavx2")
    endif()
endif()

target_link_libraries(scion-cpp
    PUBLIC
        Boost::headers
        Boost::json
        protobuf::libprotobuf
        gRPC::grpc
        gRPC::grpc++
        scion_agrpc
    PRIVATE
        $<BUILD_INTERFACE:botan>
        $<BUILD_INTERFACE:scion-proto>
)
target_include_directories(scion-cpp SYSTEM PUBLIC
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/scion>"
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated>"
    # Generated protobuf headers include each other relative to the scion/
    # directory, so include that too.
    "$<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/generated/scion>"
)
target_compile_features(scion-cpp PUBLIC cxx_std_23)

set_target_properties(scion-cpp PROPERTIES
    OUTPUT_NAME "scion++"
    EXPORT_NAME "cpp"
    DEBUG_POSTFIX "d"
    VERSION "${PROJECT_VERSION}"
    SOVERSION "${PROJECT_VERSION_MAJOR}"
)
add_library(scion::cpp ALIAS scion-cpp)

install(TARGETS scion-cpp
    COMPONENT SCION_CPP_DEV
    EXPORT scion-cpp-targets
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
    EXPORT_NAME "c-static"
    DEBUG_POSTFIX "d"
)
add_library(scion::c-static ALIAS scion-c-static)

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
    EXPORT_NAME "c"
    # Rename import library file on DLL platforms (Windows) to avoid name
    # conflict with static library.
    ARCHIVE_OUTPUT_NAME "scionc-import"
    DEBUG_POSTFIX "d"
    VERSION "${SCION_C_VERSION}"
    SOVERSION "${SCION_C_SO_VERSION}"
)
add_library(scion::c ALIAS scion-c)

install(TARGETS scion-c-static scion-c
    EXPORT scion-c-targets
    FILE_SET public_headers COMPONENT SCIONC_DEV
    ARCHIVE                 COMPONENT SCIONC_DEV
    LIBRARY                 COMPONENT SCIONC     NAMELINK_COMPONENT SCIONC_DEV
    RUNTIME                 COMPONENT SCIONC
)
install(TARGETS scion-c
    COMPONENT SCIONC
    RUNTIME
)

# ====================
# CMake Package Export
# ====================

set(SCION_CPP_CMAKE_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/scion-cpp")

configure_package_config_file(
    "cmake/scion-cpp-config.cmake.in"
    "${PROJECT_BINARY_DIR}/scion-cpp-config.cmake"
    INSTALL_DESTINATION "${SCION_CPP_CMAKE_DIR}"
)
write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/scion-cpp-config-version.cmake"
    COMPATIBILITY ExactVersion # TODO: change to SameMajorVersion after 1.0.0
)

install(FILES
    "${PROJECT_BINARY_DIR}/scion-cpp-config.cmake"
    "${PROJECT_BINARY_DIR}/scion-cpp-config-version.cmake"
    "cmake/scion-cpp-dependencies.cmake"
    COMPONENT SCION_CPP_DEV
    DESTINATION "${SCION_CPP_CMAKE_DIR}"
)
install(EXPORT scion-cpp-targets
    NAMESPACE scion::
    COMPONENT SCION_CPP_DEV
    DESTINATION "${SCION_CPP_CMAKE_DIR}"
)
install(EXPORT scion-c-targets
    NAMESPACE scion::
    COMPONENT SCIONC_DEV
    DESTINATION "${SCION_CPP_CMAKE_DIR}"
)

# ==========
# Unit Tests
# ==========

if(SCION_CPP_BUILD_TESTS)

enable_testing()
include(GoogleTest)
scion_add_googletest()

# Test utilities shared with application tests
add_library(scion_test_utils STATIC "tests/utilities.cpp")
target_include_directories(scion_test_utils PUBLIC "${PROJECT_SOURCE_DIR}/tests")
target_link_libraries(scion_test_utils PUBLIC scion::cpp gtest)

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
    "tests/extensions/test_idint_details.cpp"
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
)

add_executable(unit-tests ${SRC_TEST})
target_link_libraries(unit-tests PRIVATE
    gtest gmock scion::cpp scion::c-static scion_test_utils)

gtest_discover_tests(unit-tests
    EXTRA_ARGS "${PROJECT_SOURCE_DIR}/tests"
)

endif(SCION_CPP_BUILD_TESTS)

# ========
# Examples
# ========

if(SCION_CPP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ============
# Applications
# ============

if(SCION_CPP_BUILD_APPS)
    if(LINUX)
        add_subdirectory(interposer)
        add_subdirectory(scitra)
        add_subdirectory(scitra/tools/scion2ip)
    endif()
endif()

# =========
# Packaging
# =========

if(PROJECT_IS_TOP_LEVEL)

# scion++-dev
set(CPACK_COMPONENT_SCION_CPP_DEV_DESCRIPTION "SCION SDK for C++")
set(CPACK_DEBIAN_SCION_CPP_DEV_PACKAGE_NAME "scion++-dev")

set(CPACK_RPM_SCION_CPP_DEV_PACKAGE_SUMMARY "${CPACK_COMPONENT_SCION_CPP_DEV_DESCRIPTION}")
set(CPACK_RPM_SCION_CPP_DEV_PACKAGE_NAME "scion++-devel")

if(SCION_OS_ID STREQUAL "debian" OR SCION_OS_ID_LIKE MATCHES "debian")
    scion_get_dep_versions(deb CPACK_DEBIAN_SCION_CPP_DEV_PACKAGE_DEPENDS
        SAME_MAJOR
            libc-ares-dev
        SAME_MINOR
            libboost-dev
            libboost-json-dev
            libgrpc++-dev
            libprotobuf-dev
    )
elseif(SCION_OS_ID STREQUAL "fedora" OR SCION_OS_ID_LIKE MATCHES "fedora")
    scion_get_dep_versions(rpm CPACK_RPM_SCION_CPP_DEV_PACKAGE_REQUIRES
        SAME_MAJOR
            c-ares-devel
        SAME_MINOR
            boost-devel
            grpc-devel
            protobuf3-devel
    )
else()
    message(WARNING "No dependency list for build host OS, the package will have no dependencies.")
endif()

# scionc-dev
set(CPACK_COMPONENT_SCIONC_DEV_DESCRIPTION "SCION C++ SDK C interface headers")
set(CPACK_DEBIAN_SCIONC_DEV_PACKAGE_NAME "scionc-dev")
string(CONCAT CPACK_DEBIAN_SCIONC_DEV_PACKAGE_DEPENDS
    "scion++-dev (= ${PROJECT_VERSION}-${SCION_PACKAGE_RELEASE}), "
    "scionc (= ${PROJECT_VERSION}-${SCION_PACKAGE_RELEASE})"
)

set(CPACK_RPM_SCIONC_DEV_PACKAGE_NAME "scionc-devel")
set(CPACK_RPM_SCIONC_DEV_PACKAGE_SUMMARY "${CPACK_COMPONENT_SCIONC_DEV_DESCRIPTION}")
string(CONCAT CPACK_RPM_SCIONC_DEV_PACKAGE_REQUIRES
    "scion++-devel = ${PROJECT_VERSION}-${SCION_PACKAGE_RELEASE}, "
    "scionc = ${PROJECT_VERSION}-${SCION_PACKAGE_RELEASE}"
)

# scionc
set(CPACK_DEBIAN_SCIONC_DESCRIPTION "SCION C SDK runtime files")
set(CPACK_DEBIAN_SCIONC_PACKAGE_NAME "scionc")

set(CPACK_RPM_SCIONC_PACKAGE_NAME "scionc")
set(CPACK_RPM_SCIONC_PACKAGE_SUMMARY "${CPACK_DEBIAN_SCIONC_DESCRIPTION}")

# The SCION SDK packages are relocatable, only application packages contain
# absolute paths.
scion_configure_cpack(
    RELOCATABLE
    COMPONENTS
        SCION_CPP_DEV
        SCIONC_DEV
        SCIONC
)

endif(PROJECT_IS_TOP_LEVEL)
