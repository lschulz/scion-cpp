SCION-CPP: SCION Endhost Libraries and Applications
===================================================

This repository contains the scion-cpp library, its C bindings, and applications built on top of it.
Currently available are:
- [SCION-IP Translators](./scitra/): Seamlessly use SCION from legacy applications and networks.
  - [Scitra-TUN](./scitra/docs/scitra-tun.md)
- [SCION API Interposers](./interposer/): Deep SCION integration without touching application code.

### Dependencies
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

### Building
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

### Installation
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

### Build Debian Packages with CPack

When building DEB packages `CPACK_SET_DESTDIR` must be set during the configuration step to
correctly install configuration files in /etc/scion. If `CPACK_SET_DESTDIR` is not set, the DEB
packages will incorrectly install configuration files in /usr/etc/scion. `CPACK_SET_DESTDIR` is not
set by default because it also results in the generated build-system's install target to install
configuration files to /etc/scion ignoring `CMAKE_INSTALL_PREFIX`.

Background: In order to install to /etc/scion an absolute path is given to `install()`, using
a relative path or `CMAKE_INSTALL_SYSCONFDIR` results in a path prefixed with /usr. Using an
absolute path is not a perfect solution however, since absolute paths only work for the
DEB packages not necessarily for other CPack generators or manual installation.

```bash
mkdir build
cmake -G 'Ninja Multi-Config' -B build -DCPACK_SET_DESTDIR=ON -DCMAKE_INSTALL_PREFIX=/
make deb
```

### Unit Tests

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

### Integration Tests

The integration tests require a copy of the [SCION source code](https://github.com/scionproto/scion).
Set `SCION_ROOT` to the root of the repository.
```bash
make SCION_ROOT=~/scionproto-scion test-integration
```

### Examples

- `examples/echo_udp`: UDP echo client and server using blocking sockets.
- `examples/echo_udp_async`: UDP echo client and server using coroutines.
- `examples/traceroute`: Illustrates sending and receiving SCMP messages using
  coroutines.
- `examples/resolver`: Example of resolving symbolic host names to SCION
  addresses.
- `examples/c`: C interface examples.
