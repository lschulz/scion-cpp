SCION-CPP: SCION C++ and IP Compatibility SDK
=============================================

This repository contains a C++ applications SDK (with optional C bindings) for the [SCION Internet
architecture](https://www.scion.org/). It is intended for both end host applications and SCION
middleboxes such as address translators. Included are many example applications as well as
compatibility layers for porting existing IP-based applications to SCION even if their source code
is unavailable.

The main parts of the SDK are:
- **scion++** (*libscion++*) The main C++ SCION library. Designed as a toolbox that comes with
  everything a SCION application needs but doesn't lock the application developer into just one
  approach to network I/O.
- **scionc** (*libscionc*) C bindings for scion++ sockets.
- **scion-interposer** A libc interceptor library that emulates OS-native SCION support
- **scitra-tun** A SCION-IP translator that enables IPv6 applications to communicate over a SCION
  backbone as well as mixed IPv6 and SCION client/server compatibility.

### Features ###
- SCION packet parsing and emitting
- SCION path manipulation
- Path and Path MTU cache
- SCMP and UDP/SCION sockets
- BSD/POSIX socket API for easy porting of existing applications
- ASIO socket API for flexible asynchronous I/O
- Name resolution
- Path policies
- Path MTU discovery
- STUN for SCION hosts behind NAT
- Secure in-band telemetry ([ID-INT](https://github.com/netsys-lab/id-int-spec))
- Supports Linux and Windows hosts

### C Compatibility ###
Pure C applications may use the SDK via C bindings to the ASIO socket API in *libscionc* or by
taking advantage of the *scion-interposer* that replaces many socket related functions in *libc*
with SCION-aware wrappers.

### Included Applications ###
- [SCION-IP Translators](scitra/): Seamlessly use SCION from legacy applications and networks.
  - [Scitra-TUN](scitra/docs/scitra-tun.md) A SCION-IP translator using TUN interfaces on Linux.
- [SCION API Interposers](interposer/): Deep SCION integration without touching application code.
    Currently only available for glibc in Linux-like environments.

### Documentation ###
API documentation is generated with Doxygen.
```bash
make docs
python3 -m http.server -d build/docs/html
```

Miscellaneous topics:
- [NAT traversal with STUN](docs/nat_traversal.md)

man pages:
- [scion2ip(1)](scitra/tools/scion2ip/man/scion2ip.1.md)
- [scitra-tun(8)](scitra/man/scitra-tun.8.md)
- [scitra-policy.json(5)](scitra/man/scitra-policy.json.5.md)
- [scion-interposer(7)](interposer/man/scion-interposer.7.md)

### API Examples ###
- [examples/echo_udp](examples/echo_udp/main.cpp): UDP echo server and client using blocking
  POSIX-style socket API. Also shows how to use STUN to traverse NAT between SCION hosts and
  routers.
- [examples/echo_udp_async](examples/echo_udp_async/main.cpp): UDP echo server and client using
  C++20 coroutines with the ASIO API. Supports STUN.
- [examples/c/echo_udp](examples/c/echo_udp/main.c): Example of the C bindings with blocking I/O
  and support for STUN.
- [examples/c/ech_udp_async](examples/c/echo_udp_async/main.c): Example of the C bindings with
  callback-based asynchronous I/O and support for STUN.
- [examples/pmtu](examples/pmtu/main.cpp): Path MTU discovery with SCMP.
- [examples/resolver](examples/resolver/main.cpp): Name resolution using SCION hosts files and DNS.
- [examples/traceroute](examples/traceroute/main.cpp): A simple implementation of SCION traceroute.
- [examples/idint-traceroute](examples/idint-traceroute/): An applications that collects path
  information with in-band telemetry. Illustrates sending and receiving packets with the ID-INT
  extension.

Using the SDK in CMake Projects
-------------------------------

Once installed, the SDK's main library `scion-cpp` and the C interface `scionc` can be imported with
`find_package`. If the SDK is not installed to system-wide, include its installation directory in
`CMAKE_PREFIX_PATH`.
```cmake
find_package(scion-cpp 0.0.5 REQUIRED) # Main C++ library
find_package(scion-cpp 0.0.5 REQUIRED COMPONENT c) ' Main library and C interface
target_link_libraries(app PRIVATE scion::cpp)
target_link_libraries(app PRIVATE scion::c) # or scion::c-static for static linkage
```

Alternatively, the repository can be build as part of your project with `FetchContent`. Tests,
examples, and applications are not built if scion-cpp is not the top-level project, except if
explicitly requested by the configuration variables `SCION_CPP_BUILD_{TESTS|EXAMPLES|APPS}`.
```cmake
cmake_minimum_required(VERSION 3.28)
project(my-project CXX)

include(FetchContent)
FetchContent_Declare(scion-cpp
  GIT_REPOSITORY https://github.com/lschulz/scion-cpp.git
  GIT_TAG        v0.5.0
)
FetchContent_MakeAvailable(scion-cpp)

add_executable(app main.cpp)
target_link_libraries(app PRIVATE scion::cpp) # or scion::c or scion::c-static
```

Using the Applications
----------------------

To use the included applications, build the entire repository as described in the Building section.
Man pages are generated with `make man`.

Building
--------

### Repository Structure ###
```
cmake ............. CMake build configuration files
deps .............. Included dependencies as submodules
docker ............ Docker container build files for development and deployment of included applications
docs .............. Miscellaneous documentation
examples .......... API examples
include ........... Header files for scion++ and scionc
integration-tests . Integration tests implemented in Python's unittest module
interposer ........ Source code, tests, and documentation of the *scion-interposer* library
proto ............. Protobuf definitions of the SCION control plane protocol
python ............ Python build and test helpers
scitra ............ SCION-IP translator libraries, applications and documentation
src ............... Source code of scion++ and scionc
test .............. scion++ and scionc unit tests
```

Make sure to initialize the submodules in `deps/`.
```bash
git submodule update --init --recursive
```

### Dependencies ###

- Boost >= 1.83.0
- Protobuf >= 3.21.12
- gRPC >= 1.51.1
- c-ares >= 1.27.0
- ncurses for the examples on platforms other than Windows
- pandoc for generating man pages
- [asio-grpc](https://github.com/Tradias/asio-grpc) (included as submodule)
- [googletest](https://github.com/google/googletest) (included as submodule)
- [CLI11](https://github.com/CLIUtils/CLI11) (included as submodule)

For scitra-tun (Linux only):
- libmnl >= 1.0.5
- libcap >= 2.66
- libsystemd >= 255.4
- libbsd >= 0.12.1
- [ImTui](https://github.com/ggerganov/imtui) (included as submodule)
- [spdlog](https://github.com/gabime/spdlog) (included as submodule)

For interposer (Linux only):
- [re2](https://github.com/google/re2)
- [toml++](https://marzer.github.io/tomlplusplus/)

Most dependencies can be downloaded and built with vcpkg:
```bash
vcpkg install
```
In Linux, `libmnl` and `libbsd` must be installed using the system's package manager.
Additionally, vcpkg currently requires `autoconf`, `autoconf-archive`, `automake`, and `libtoolize`
from the system package manager.
```bash
# Ubuntu
sudo apt-get install libmnl-dev libbsd-dev autoconf autoconf-archive automake libtool
# Fedora
sudo dnf install libmnl-devel libbsd-devel autoconf autoconf-archive automake libtool
```

In Ubuntu (24.04 and 26-04), all required build tools and dependencies can be installed with apt.
```bash
sudo apt-get install \
  build-essential \
  cmake \
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
  protobuf-compiler-grpc
```

In Fedora (45), install the following packages.
```bash
sudo dnf install \
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
```

### Building with CMake ###
Requires a C++23 compiler. gcc 13.3.0, clang 19.1.1 and MSVC 19.51.36252 work.

Building with CMake and Ninja:
```bash
mkdir build
cmake -G 'Ninja Multi-Config' -B build
cmake --build build --config Debug
cmake --build build --config Release
```

The repository provides CMake presets for compiling with vcpkg. Dependencies (except the
system-level dependencies) are downloaded and built by vcpkg.
```bash
cmake --preset=<preset>
cmake --build build --config Debug
cmake --build build --config Release
```
Available presets:
- `vcpkg-linux-gcc` compile on Linux with GCC
- `vcpkg-linux-clang` compile on Linux with Clang
- `vcpkg-vs-17` for Visual Studio 17 2022
- `vcpkg-vs-18` for Visual Studio 19 2026

### Installation ###
```bash
make man
cmake --install build --config Release
```
Installs the scion++ and scionc libraries as well as application binaries for scitra-tun and the
interposer.

The install location is determined by `CMAKE_INSTALL_PREFIX` set during the cmake configuration
step.
```bash
cmake -G 'Ninja Multi-Config' -B build -DCMAKE_INSTALL_PREFIX=$PWD/install
```

### Build Debian and RPM Packages with CPack ###

The repository is configure for building deb and rpm packages on Ubuntu and Fedora, respectively.
System package dependencies are are added automatically with the package versions currently
installed in the build environment. You can still build the packages on a different OS, but the
system package dependencies will be missing.

Applications packages must be built from a build directory configured with `CMAKE_INSTALL_PREFIX=/`.
Otherwise, configuration files that are supposed to be installed to `/etc/scion/` are incorrectly
installed in `/usr/etc/scion/`. There is no such limitation for the library (scion-cpp, scionc)
packages as they do not install files at absolute paths.

```bash
mkdir build
cmake -G 'Ninja Multi-Config' -B build -DMARCH='' -DCMAKE_INSTALL_PREFIX=/
make deb # or rpm
```

Individual subprojects can be packaged by invoking cpack directly, as every subproject has its own
CPack configuration.
```bash
cpack -G DEB --config build/CPackConfig.cmake # scion-cpp and scionc
cpack -G DEB --config build/scitra/CPackConfig.cmake
cpack -G DEB --config build/scitra/tools/scion2ip/CPackConfig.cmake
cpack -G DEB --config build/interposer/CPackConfig.cmake
```

By default, the packages have a pre-release version number of the format `major.minor.patch-commit`.
Set the CMake cache variable `RELEASE=YES` to build release packages. Release packages can also be
built in Docker containers by invoking the make targets `deb-docker-ubuntu24`, `deb-docker-ubuntu26`
and `rpm-docker-fedora`.

Tests
-----

### Unit Tests ###

Running the unit tests:
```bash
# Set TEST_BASE_PATH to the absolute path of the tests/ directory.
export TEST_BASE_PATH=$(realpath tests)
build/Debug/unit-tests
export TEST_BASE_PATH=$(realpath scitra/tests)
build/scitra/Debug/scitra-tests
export SCION_CONFIG="$PWD/interposer/integration/config/scion_interposer.toml"
build/interposer/Debug/interposer-tests
# Or run
make test
make test-scitra
make test-interposer
```

Make or update test data:
```bash
# Prepare venv
python3 -m venv .venv
. .venv/bin/activate
pip install -r python/requirements.txt
pip install -e python/scapy-scion-int[extras]
make test-data
```

### Integration Tests ###

The integration tests require a copy of the [SCION source code](https://github.com/scionproto/scion).
Some tests rely on experimental support for ID-INT, which is available from the `idint2026` branch
of [this fork](https://github.com/lschulz/scion).
Additionally, the command line tools `ip`, `ping`, `ss`, `nc`, `iperf3`, and `mptcpize` must be
available, which can be installed with apt on Ubuntu (24.04).
```bash
sudo apt-get install \
  iperf3 \
  iproute2 \
  iputils-ping \
  mptcpize
```

Set `SCION_ROOT` to the root of the repository and run the test through make or invoke the
individual Python test files directly.
```bash
make SCION_ROOT=~/scion test-integration
```
