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

#include "scitra/scitra-tun/error_codes.hpp"
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

    /// \brief Get the current MTU of interface `dev`.
    Maybe<std::uint32_t> getInterfaceMTU(const std::string& dev);

    /// \brief Set the MTU of interface `dev`.
    std::error_code setInterfaceMTU(const std::string& dev, std::uint32_t mtu);

    /// \brief Add an address to interface `dev`.
    std::error_code addAddress(const IPAddress& addr, PrefixLen prefixlen, const std::string& dev)
    {
        return modAddress(addr, prefixlen, dev, false);
    }

    /// \brief Remove an address from interface `dev`.
    std::error_code delAddress(const IPAddress& addr, PrefixLen prefixlen, const std::string& dev)
    {
        return modAddress(addr, prefixlen, dev, true);
    }

    /// \brief Index of the main routing table.
    static const std::uint8_t TABLE_MAIN;

    /// \brief Add a route to the IPv4/6 network `dst` via `interface dev` to
    /// the routing table with index `table`. The gateway router can optionally
    /// be set by supplying an IP address in `via`.
    std::error_code addRoute(
        std::uint8_t table, const IPAddress& dst, PrefixLen prefixlen,
        const std::string& dev, const IPAddress* via = nullptr);

    /// \brief Remove all routes to the IPv4/6 network `dst` via `dev` from the
    /// routing table with index `table`.
    std::error_code delRoute(
        std::uint8_t table, const IPAddress& dst, PrefixLen prefixlen, const std::string& dev);

    /// \brief Add a source routing rule to the routing policy database that
    /// causes packets with a source address matching `src` (with prefix length
    /// `prefixlen`) to be routed according to the routing table with the index
    /// `table`.
    std::error_code addSourceRoutingRule(
        const IPAddress& src, PrefixLen prefixlen, std::uint8_t table);

private:
    std::error_code modAddress(
        const IPAddress& addr, PrefixLen prefixlen, const std::string& dev, bool del);
    std::error_code execute(nlmsghdr* nlh, char* buf, size_t bufsize, unsigned int seq);

private:
    mnl_socket* nl = nullptr;
    uint32_t seq = 0;
};
