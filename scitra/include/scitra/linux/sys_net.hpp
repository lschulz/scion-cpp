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

#pragma once

#include "scion/addr/generic_ip.hpp"

#include <cstdint>
#include <vector>


using Inode = unsigned long;

/// \brief General information about a socket.
struct SocketInfo
{
    scion::generic::IPAddress localAddr;
    scion::generic::IPAddress remoteAddr;
    std::uint16_t localPort;
    std::uint16_t remotePort;
    unsigned int state;
    Inode inode;
};

/// \brief Gets the inodes corresponding to sockets that are referenced by the
/// calling process.
/// \param reserve How much space to reserve in the returned vector.
std::vector<Inode> getSocketInodes(std::size_t reserve);

/// \brief Lists all UDP/IPv6 sockets system-wide.
/// \param reserve How much space to reserve in the returned vector.
std::vector<SocketInfo> getSocketsUdp6(std::size_t reserve);

/// \brief Lists all TCP/IPv6 sockets system-wide.
/// \param reserve How much space to reserve in the returned vector.
std::vector<SocketInfo> getSocketsTcp6(std::size_t reserve);
