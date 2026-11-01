#!/bin/sh

# Build out-of-tree
mkdir /build
cmake -G 'Ninja Multi-Config' -S /scion-cpp -B /build \
    -DMARCH='' -DCPACK_SET_DESTDIR=ON -DCMAKE_INSTALL_PREFIX=/ -DRELEASE=YES
cmake --build /build --config Release

# Package
mkdir /package
cd /package && cpack -G DEB --config /build/CPackConfig.cmake

# Copy results
source /etc/os-release
subdir="$ID$VERSION_ID"
mkdir -p /out/$subdir
cat /package/*.sha256 > "/out/$subdir/checksums.sha256"
cp /package/*.deb "/out/$subdir"
chown -R ${HOST_UID} "/out/$subdir"
