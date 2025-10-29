SCION-CPP: A SCION Client Library in C++
========================================

Still a work in progress.

### Dependencies
- Boost >= 1.83.0
- Protobuf >= 3.21.12
- gRPC >= 1.51.1
- c-ares >= 1.27.0
- ncurses for the examples on platforms other than Windows
- [asio-grpc](https://github.com/Tradias/asio-grpc) (included as submodule)
- [googletest](https://github.com/google/googletest) (included as submodule)
- [CLI11](https://github.com/CLIUtils/CLI11) (included as submodule)

For scitra-tun (Linux only):
- liburing >= 2.5
- libmnl >= 1.0.5

For interposer (Linux only):
- [re2](https://github.com/google/re2)
- [toml++](https://marzer.github.io/tomlplusplus/)

Dependencies can be installed locally with vcpkg:
```bash
vcpkg install
```

Make sure to initialize the submodules in `deps/`
```bash
git submodule update --init
```

### Building
Requires a C++23 compiler. gcc 13.3.0, clang 19.1.1, and MSVC 19.44.35209 work.

Building with CMake and Ninja:
```bash
mkdir build
cmake -G 'Ninja Multi-Config' -B build
cmake --build build --config Debug
```

CMake preset for Windows:
```bash
cmake --preset=vcpkg-vs
cmake --build build --config Debug
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
