# syntax=docker/dockerfile:1

FROM ubuntu:26.04

# Install build dependencies
RUN apt-get update && apt-get -y upgrade && apt-get -y install \
    build-essential \
    cmake \
    file \
    libboost-dev \
    libboost-json-dev \
    libbsd-dev \
    libc-ares-dev \
    libcap-dev \
    libgrpc++-dev \
    libmnl-dev \
    libncurses-dev \
    libprotobuf-dev \
    libre2-dev \
    libsystemd-dev \
    libtomlplusplus-dev \
    ninja-build \
    pandoc \
    protobuf-compiler \
    protobuf-compiler-grpc \
    python3

# Build scripts expects source in /scion-cpp and writes output to /out
COPY build.sh /

# Build packages
CMD ["bash", "build.sh"]
