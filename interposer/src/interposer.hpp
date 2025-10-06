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

#include "interposer.h"
#include "control_plane.hpp"
#include "options.hpp"
#include "selector.hpp"

#include "scion/addr/mapping.hpp"
#include "scion/details/c_interface.hpp"
#include "scion/error_codes.hpp"
#include "scion/path/shared_cache.hpp"
#include "scion/posix/sockaddr.hpp"
#include "scion/posix/udp_socket.hpp"
#include "scion/posix/underlay.hpp"
#include "scion/resolver.hpp"
#include "scion/scmp/path_mtu.hpp"

#include <cstdlib>
#include <cstdlib>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <system_error>
#include <unordered_map>


class AddressSurrogates
{
private:
    mutable std::shared_mutex m_mutex;
    std::unordered_map<scion::generic::IPAddress, scion::ScIPAddress> m_surrogates;
    std::unordered_map<scion::ScIPAddress, scion::generic::IPAddress> m_addresses;

public:
    // Create a new surrogate IP address for the given SCION address or return
    // the existing one.
    scion::generic::IPAddress makeSurrogate(const scion::ScIPAddress& addr)
    {
        using namespace scion;
        std::unique_lock guard(m_mutex);
        if (auto i = m_addresses.find(addr); i != m_addresses.end()) {
            return i->second;
        } else {
            std::hash<ScIPAddress> h;
            auto surrogate = generic::IPAddress::MakeIPv6(0xfcull << 56, h(addr));
            for (size_t i = 1; m_surrogates.contains(surrogate); ++i) {
                surrogate = generic::IPAddress::MakeIPv6(0xfcull << 56, h(addr) + i);
            }
            m_surrogates[surrogate] = addr;
            m_addresses[addr] = surrogate;
            return surrogate;
        }
    }

    // Add a new surrogate IP and SCION address pair, overwriting any previous
    // bindin for the same surrogate address.
    void addOrReplace(const scion::generic::IPAddress& surrogate, const scion::ScIPAddress& addr)
    {
        std::unique_lock guard(m_mutex);
        m_surrogates[surrogate] = addr;
        m_addresses[addr] = surrogate;
    }

    // Retrieve the SCION address associated with a given surrogate address.
    std::optional<scion::ScIPAddress> getAddress(const scion::generic::IPAddress& surrogate) const
    {
        using namespace scion;
        std::shared_lock guard(m_mutex);
        if (auto i = m_surrogates.find(surrogate); i != m_surrogates.end()) {
            return i->second;
        } else {
            return std::nullopt;
        }
    }
};

struct CachedDestination
{
    scion::ScIPEndpoint dst;
    scion::posix::IPEndpoint nh;
    scion::PathPtr path;
};

// TODO: Split DgramSocket and StreamSocket
struct Socket
{
    int family = 0; // AF_INET6 or AF_SCION
    int type = 0;
    int protocol = 0;

    // Mutex protecting the socket from concurrent access
    std::mutex mutex;

    // User-supplied pointer for path selector callbacks
    void* selectorCtx = nullptr;

    // Destination for which headerCache still holds a valid header
    std::optional<CachedDestination> lastDest;
    scion::HeaderCache<> headerCache;

    // SCION socket
    std::variant<std::monostate, scion::posix::IpUdpSocket> s;

    Socket(int family, int protocol, scion::posix::IpUdpSocket&& udp)
        : family(family), type(SOCK_DGRAM), protocol(protocol), s(std::move(udp))
    {
        assert(family == AF_INET || family == AF_INET6 || family == AF_SCION);
    }
};

class Interposer
{
public:
    explicit Interposer(const Options& opts);
    ~Interposer();

    // Get control plane connection initializing it if necessary.
    ControlPlane* cp();

    std::shared_mutex mutex;
    const AddressMode mode = AddressMode::ADDRESS_MAPPING;
    const bool extendedAddressMapping = true;
    const bool allowPromoteOnSendTo = false;
    const std::optional<scion::generic::IPAddress> defaultIPv4;
    const std::optional<scion::generic::IPAddress> defaultIPv6;
    PathSelector selector = {};

    const bool connectToDaemon = true;
    const std::string daemonAddress;

    scion::PathMtuDiscoverer<> pmtu;
    scion::Resolver resolver;
    scion::SharedPathCache pathCache;
    AddressSurrogates surrogates;
    std::unordered_map<NativeSocket, std::unique_ptr<Socket>> sockets;

private:
    std::mutex cpMutex;
    std::unique_ptr<ControlPlane> controlPlane;
};
