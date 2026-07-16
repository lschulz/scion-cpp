// Copyright (c) 2026 Lars-Christian Schulz
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
#include <string>
#include <vector>


namespace scion {
namespace scitra {
namespace mptcpd {

using Token = std::uint32_t;
using AddressId = std::uint8_t;
using MpTcpFlags = std::uint32_t; // Rename: MptcpdFlags

struct Interface
{
    unsigned char family = 0;
    unsigned short type = 0;
    unsigned int flags = 0;
    std::string name;
    std::vector<generic::IPAddress> addresses;
};

struct AddrInfo
{
    generic::IPAddress addr;
    std::uint8_t id = 0; // TODO: type
    std::uint32_t flags = 0;
    int index = 0;
};

struct MpTcpLimit
{
    std::uint16_t type;
    std::uint32_t limit;
};

enum class Function
{
    // Path Manager Events (Plugin->Scitra)
    NewConnection = 1,
    ConnectionEstablished,
    ConnectionClosed,
    NewAddress,
    AddressRemoved,
    NewSubflow,
    SubflowClosed,
    SubflowPriority,
    ListenerCreated,
    ListenerClosed,

    // Network Monitor Events (Plugin->Scitra)
    NewInterface = 16,
    UpdateInterface,
    DeleteInterface,
    NewLocalAddress,
    DeleteLocalAddress,

    // Userspace Path Manager API (Scitra->Plugin)
    PmReady = 32,
    PmAddAddr,
    PmAddAddrNoListener,
    PmRemoveAddr,
    PmAddSubflow,
    PmSetBackup,
    PmRemoveSubflow,

    // Kernel Path Manager API (Scitra->Plugin)
    KpmAddAddr = 48,
    KpmRemoveAddr,
    KpmGetAddr,
    KpmDumpAddrs,
    KpmFlushAddrs,
    KpmSetLimits,
    KpmGetLimits,
    KpmSetFlags,
};

} // namespace mptcpd
} // namespace scitra
} // namespace scion
