#!/bin/sh

# Build out-of-tree
mkdir /build
cmake -G 'Ninja Multi-Config' -S /scion-cpp -B /build \
    -DCPACK_SET_DESTDIR=ON -DCMAKE_INSTALL_PREFIX=/ -DRELEASE=YES
cmake --build /build --config Release

# Package
mkdir /package
cd /package && cpack -G DEB --config /build/CPackConfig.cmake

# Copy results
cat /package/*.sha256 > /out/checksums.sha256
cp /package/*.deb /out
chown ${HOST_UID} /out/*
