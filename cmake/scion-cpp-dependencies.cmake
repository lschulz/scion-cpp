# Locates the external dependencies of scion-cpp.

# =====
# Boost
# =====

find_package(Boost CONFIG REQUIRED COMPONENTS json)

# ========
# Protobuf
# ========

if(NOT TARGET protobuf::libprotobuf)
    find_package(Protobuf CONFIG QUIET)
endif()
if(NOT TARGET protobuf::libprotobuf)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(protobuf_pkg REQUIRED IMPORTED_TARGET protobuf)
    add_library(protobuf::libprotobuf INTERFACE IMPORTED)
    target_link_libraries(protobuf::libprotobuf INTERFACE PkgConfig::protobuf_pkg)
endif()

# ====
# gRPC
# ====

if(NOT TARGET gRPC::grpc++)
    find_package(gRPC CONFIG QUIET)
endif()
if(NOT TARGET gRPC::grpc++)
    find_package(PkgConfig REQUIRED)

    pkg_check_modules(grpc_pkg REQUIRED IMPORTED_TARGET grpc)
    add_library(gRPC::grpc INTERFACE IMPORTED)
    target_link_libraries(gRPC::grpc INTERFACE PkgConfig::grpc_pkg)

    pkg_check_modules(grpcpp_pkg REQUIRED IMPORTED_TARGET grpc++)
    add_library(gRPC::grpc++ INTERFACE IMPORTED)
    target_link_libraries(gRPC::grpc++ INTERFACE PkgConfig::grpcpp_pkg)
endif()
