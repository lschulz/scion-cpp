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

#include "scitra/linux/error_codes.hpp"
#include "scion/addr/generic_ip.hpp"

#include <boost/asio.hpp>
#include <libmnl/libmnl.h>

#include <string>
#include <system_error>

using namespace scion;


/// \brief Provides network configuration via a netlink ROUTE socket.
class NetlinkRoute
{
public:
    NetlinkRoute();
    NetlinkRoute(const NetlinkRoute& other) = delete;
    NetlinkRoute& operator=(const NetlinkRoute& other) = delete;

    /// \brief Open NetlinkRoute socket.
    std::error_code open();

    void close();

    ~NetlinkRoute() { close(); }

    using IPAddress = scion::generic::IPAddress;
    using PrefixLen = unsigned char;

    /// \brief Set a network interface administratively up or down. Equivalent
    /// to "ip link set dev <dev> up".
    std::error_code setInterfaceState(const std::string& dev, bool up);

    Maybe<std::uint32_t> getInterfaceMTU(const std::string& dev);
    std::error_code setInterfaceMTU(const std::string& dev, std::uint32_t mtu);

    std::error_code addAddress(const IPAddress& addr, PrefixLen prefixlen, const std::string& dev)
    {
        return modAddress(addr, prefixlen, dev, false);
    }

    std::error_code delAddress(const IPAddress& addr, PrefixLen prefixlen, const std::string& dev)
    {
        return modAddress(addr, prefixlen, dev, true);
    }

    /// \brief Add a route to the IPv4/6 network `dst` via `dev` to the routing
    /// table.
    std::error_code addRoute(
        const IPAddress& dst, PrefixLen prefixlen, const std::string& dev, int metric = 256);

    /// \brief Remove the route to the IPv4/6 network `dst` via `dev` from the
    /// routing table.
    std::error_code delRoute(const IPAddress& dst, PrefixLen prefixlen, const std::string& dev);

private:
    std::error_code modAddress(
        const IPAddress& addr, PrefixLen prefixlen, const std::string& dev, bool del);
    std::error_code execute(nlmsghdr* nlh, char* buf, size_t bufsize);

private:
    mnl_socket* nl = nullptr;
    uint32_t seq = 0;
};
