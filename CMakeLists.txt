cmake_minimum_required(VERSION 3.28)

project(scion-cpp C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
add_compile_options(/W3)
else()
add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
endif()

if (WIN32)
add_compile_definitions(NOMINMAX)
endif()

# =====
# Boost
# =====

find_package(Boost CONFIG REQUIRED)

# =========================
# Protobuf, gRPC, asio-grpc
# =========================

find_package(protobuf CONFIG)

if (Protobuf_FOUND)

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

add_subdirectory(deps/asio-grpc)

# ==========
# GoogleTest
# ==========

include(GoogleTest)
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
    OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated"
    PROTOS "${PROTO_SRC}"
)

# ============
# Main Library
# ============

set(SRC
    "src/addr/endpoint.cpp"
    "src/addr/generic_ip.cpp"
    "src/addr/isd_asn.cpp"
    "src/bit_stream.cpp"
    "src/daemon/client.cpp"
    "src/default_address.cpp"
    "src/error_codes.cpp"
    "src/murmur_hash3.cpp"
    "src/path/path_meta.cpp"
    "src/path/path.cpp"
    "src/resolver.cpp"
)

add_library(scion-cpp ${SRC})
target_link_libraries(scion-cpp PUBLIC
    Boost::headers
    asio-grpc::asio-grpc
    scion-proto
)
target_include_directories(scion-cpp
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/deps/asio-grpc/src"
    PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/generated" # TODO: Install generated files
)

# ===========
# C Interface
# ===========

set(SRC_C
    "src/scion_c/scion.cpp"
    "src/scion_c/scion.c"
)

add_library(scion-c ${SRC_C})
target_link_libraries(scion-c PRIVATE scion-cpp)
target_include_directories(scion-c
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# ==========
# Unit Tests
# ==========

enable_testing()

set(SRC_TEST
    "tests/main.cpp"
    "tests/utilities.cpp"
    "tests/addr/test_isd_asn.cpp"
    "tests/addr/test_generic_ip.cpp"
    "tests/addr/test_address.cpp"
    "tests/addr/test_endpoint.cpp"
    "tests/test_bit_stream.cpp"
    "tests/hdr/test_checksum.cpp"
    "tests/hdr/test_ip.cpp"
    "tests/hdr/test_scion.cpp"
    "tests/hdr/test_scmp.cpp"
    "tests/hdr/test_idint.cpp"
    "tests/path/test_raw_path.cpp"
    "tests/path/test_decoded_scion.cpp"
    "tests/path/test_protobuf_time.cpp"
    "tests/path/test_path_meta.cpp"
    "tests/path/test_path.cpp"
    "tests/path/test_cache.cpp"
    "tests/socket/test_header_cache.cpp"
    "tests/socket/test_parsed_packet.cpp"
    "tests/socket/test_packager.cpp"
    "tests/posix/test_addr.cpp"
    "tests/posix/test_scmp_socket.cpp"
    "tests/posix/test_udp_socket.cpp"
    "tests/asio/test_addresses.cpp"
    "tests/asio/test_scmp_socket.cpp"
    "tests/asio/test_udp_socket.cpp"
    "tests/resolver/test_resolver.cpp"
    "tests/scion_c/test_c_interface.cpp"
)

add_executable(unit-tests ${SRC_TEST})
target_link_libraries(unit-tests PRIVATE gtest gmock scion-cpp scion-c)
target_include_directories(unit-tests
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

gtest_discover_tests(unit-tests
    EXTRA_ARGS "${CMAKE_CURRENT_SOURCE_DIR}/tests"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

# ========
# Examples
# ========

add_subdirectory(examples)
