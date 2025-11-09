// Copyright (c) 2024-2025 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "scitra/scitra-tun/sys_net.hpp"

#include "scion/details/bit.hpp"

#include <filesystem>
#include <fstream>
#include <string>


std::vector<Inode> getSocketInodes(std::size_t reserve)
{
    namespace fs = std::filesystem;
    std::vector<Inode> sockets;
    sockets.reserve(reserve);
    for (auto fd : fs::directory_iterator("/proc/self/fd")) {
        Inode inode = 0;
        if (std::sscanf(fs::read_symlink(fd).c_str(), "socket:[%lu]", &inode))
            sockets.push_back(inode);
    }
    return sockets;
}

static std::vector<SocketInfo> getSockets6(const char* path, std::size_t reserve)
{
    using namespace scion::generic;
    using scion::details::byteswapBE;

    std::vector<SocketInfo> sockets;
    sockets.reserve(reserve);

    std::ifstream s(path);
    if (!s.is_open()) return sockets;

    std::string line;
    unsigned int localAddr[4];
    unsigned int remAddr[4];
    unsigned int localPort;
    unsigned int remPort;
    unsigned int state;
    unsigned long inode;
    if (!std::getline(s, line)) return sockets; // discard header
    while (std::getline(s, line)) {
        // format string from get_tcp6_sock() in net/ipv6/tcp_ipv6.c
        int res = std::sscanf(line.c_str(),
            "%*4d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X "
            "%02X %*08X:%*08X %*02X:%*08X %*08X %*5u %*8d %lu",
            &localAddr[0], &localAddr[1], &localAddr[2], &localAddr[3],
            &localPort,
            &remAddr[0], &remAddr[1], &remAddr[2], &remAddr[3],
            &remPort,
            &state,
            &inode);
        if (res == 12) {
            sockets.emplace_back(
                IPAddress::MakeIPv6(
                    (uint64_t)byteswapBE(localAddr[0]) << 32
                    | (uint64_t)byteswapBE(localAddr[1]),
                    (uint64_t)byteswapBE(localAddr[2]) << 32
                    | (uint64_t)byteswapBE(localAddr[3])),
                IPAddress::MakeIPv6(
                    (uint64_t)byteswapBE(remAddr[0]) << 32
                    | (uint64_t)byteswapBE(remAddr[1]),
                    (uint64_t)byteswapBE(remAddr[2]) << 32
                    | (uint64_t)byteswapBE(remAddr[3])),
                localPort, remPort,
                state,
                inode);
        }
    }
    return sockets;
}

std::vector<SocketInfo> getSocketsUdp6(std::size_t reserve)
{
    return getSockets6("/proc/net/udp6", reserve);
}

std::vector<SocketInfo> getSocketsTcp6(std::size_t reserve)
{
    return getSockets6("/proc/net/tcp6", reserve);
}
