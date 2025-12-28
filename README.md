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

### Installation ###

Precompiled binaries of the applications and development headers for SCION++ and SCIONC are
available as deb packages for Ubuntu 24.04 in the releases section of this repository.

The packages are also available alongside the [SCION release
packages](https://github.com/scionproto/scion/releases) in an APT repository at
https://lcschulz.de/scion/apt (amd64 architecture only). You may set up the
repository in Ubuntu as follows.

```bash
sudo apt update
sudo apt install ca-certificates curl
sudo curl -fsSL https://lcschulz.de/scion/gpg/scion-lcschulz -o /usr/share/keyrings/scion-lcschulz.gpg
sudo chmod a+r /usr/share/keyrings/scion-lcschulz.gpg
sudo tee /etc/apt/sources.list.d/scion-lcschulz.list <<EOF
deb [arch=amd64 signed-by=/usr/share/keyrings/scion-lcschulz.gpg] https://lcschulz.de/scion/apt noble main
EOF
sudo apt update
```

Then install the packages.

```bash
sudo apt install scion++-dev scionc-dev scion-interposer scitra-tun
```

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
- libcap >= 3.1.3
- [ImTui](https://github.com/ggerganov/imtui) (included as submodule)
- [spdlog](https://github.com/gabime/spdlog) (included as submodule)

For interposer (Linux only):
- [re2](https://github.com/google/re2)
- [toml++](https://marzer.github.io/tomlplusplus/)

Most dependencies can be built and installed with vcpkg:
```bash
vcpkg install
```
In Linux, `libmnl` and `libcap` must be installed using the system's package manager.

All required build tools and dependencies can also be installed with apt (Ubuntu 24.04).
```bash
sudo apt-get install \
  build-essential \
  cmake \
  libboost-dev \
  libboost-json-dev \
  libc-ares-dev \
  libcap-dev \
  libgrpc++-dev \
  libmnl-dev \
  libncurses-dev \
  libprotobuf-dev \
  libre2-dev \
  libtomlplusplus-dev \
  ninja-build \
  pandoc \
  protobuf-compiler \
  protobuf-compiler-grpc
```

Make sure to initialize the submodules in `deps/`.
```bash
git submodule update --init --recursive
```

### Building with CMake ###
Requires a C++23 compiler. gcc 13.3.0, clang 19.1.1 and MSVC 19.44.35209 work.

Building with CMake and Ninja:
```bash
mkdir build
cmake -G 'Ninja Multi-Config' -B build
cmake --build build --config Debug
cmake --build build --config Release
```

CMake preset for Windows:
```bash
cmake --preset=vcpkg-vs
cmake --build build --config Debug
cmake --build build --config Release
```

### Installation ###
```bash
cmake --install build --config Release
```
Installs the scion++ and scionc libraries as well as application binaries for scitra-tun and the
interposer.

The install location is determined by `CMAKE_INSTALL_PREFIX` set during the cmake configuration
step.
```bash
cmake -G 'Ninja Multi-Config' -B build -DCMAKE_INSTALL_PREFIX=example
```

### Build Debian Packages with CPack ###

When building deb packages `CPACK_SET_DESTDIR` must be set during the configuration step to
correctly install configuration files in /etc/scion. If `CPACK_SET_DESTDIR` is not set, the deb
packages will incorrectly install configuration files in /usr/etc/scion. `CPACK_SET_DESTDIR` is not
set by default because it also results in the generated build-system's install target to install
configuration files to /etc/scion ignoring `CMAKE_INSTALL_PREFIX`.

Background: In order to install to /etc/scion an absolute path is given to `install()`, using
a relative path or `CMAKE_INSTALL_SYSCONFDIR` results in a path prefixed with /usr. Using an
absolute path is not a perfect solution however, since absolute paths only work for the
deb packages not necessarily for other CPack generators or manual installation.

```bash
mkdir build
cmake -G 'Ninja Multi-Config' -B build -DCPACK_SET_DESTDIR=ON -DCMAKE_INSTALL_PREFIX=/
make deb
```

By default, the packages have a pre-release version number of the format `major.minor.patch-commit`.
Set the CMake cache variable `RELASE=YES` to build release packages. The deb packages can also be
build in a Docker container by invoking the make target `deb-docker`. Packets build this way are
marked as release versions.

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
make test-data
```

### Integration Tests ###

The integration tests require a copy of the [SCION source code](https://github.com/scionproto/scion).
Set `SCION_ROOT` to the root of the repository.
```bash
make SCION_ROOT=~/scionproto-scion test-integration
```
