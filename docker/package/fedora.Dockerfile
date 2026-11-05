# syntax=docker/dockerfile:1

FROM fedora:45

# Install build dependencies
RUN dnf upgrade -y && dnf install -y \
    boost-devel \
    c-ares-devel \
    cmake \
    g++ \
    gcc \
    grpc-cpp \
    grpc-devel \
    libbsd-devel \
    libcap-devel \
    libmnl-devel \
    make \
    ncurses-devel \
    ninja-build \
    pandoc-cli \
    protobuf3-compiler \
    protobuf3-devel \
    re2-devel \
    rpm-build \
    systemd-devel \
    tomlplusplus-devel

# Build scripts expects source in /scion-cpp and writes output to /out
COPY build.sh /

# Build packages
CMD ["bash", "build.sh"]
