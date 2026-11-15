#!/bin/sh

source /etc/os-release

# Build out-of-tree
mkdir /build
cmake -G 'Ninja Multi-Config' -S /scion-cpp -B /build \
    -DMARCH='' -DCMAKE_INSTALL_PREFIX=/ -DRELEASE=YES \
    -DSCION_PACKAGE_RELEASE="1~${UBUNTU_CODENAME}1"
cmake --build /build --config Release

# Package
mkdir /package
cd /package
for config in \
    CPackConfig.cmake \
    scitra/CPackConfig.cmake \
    scitra/tools/scion2ip/CPackConfig.cmake \
    interposer/CPackConfig.cmake
do
    cpack -G DEB --config "/build/$config" || exit 1
done

# Copy results
subdir="${ID}${VERSION_ID}-$(uname -m)"
mkdir -p /out/$subdir
cat /package/*.sha256 > "/out/$subdir/checksums.sha256"
cp /package/*.deb "/out/$subdir"
chown -R ${HOST_UID} "/out/$subdir"
