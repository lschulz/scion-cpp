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

#include "scitra/packet.hpp"
#include "scitra/scitra-tun/debug.hpp"
#include "scitra/scitra-tun/error_codes.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>

namespace asio = boost::asio;
using namespace scion;
using namespace scion::scitra;


// Encapsulates a UDP underlay socket. Contains logic for parsing and emitting
// packets. If configured, NAT is applied to the SCION address header and L4
// ports so that NAT devices between Scitra and a border router can be
// tolerated. NAT address mappings are discovered using STUN.
class Socket
{
private:
    // IP address and port the socket is bound to. Identifies the socket.
    generic::IPEndpoint m_localEp;

    // Whether the socket is persistent or temporary.
    const bool m_persistent;

    // Underlay UDP socket for comunicating with SCION routers and hosts.
    asio::ip::udp::socket m_underlay;

    // External IP address and port after NAT.
    std::atomic<std::shared_ptr<generic::IPEndpoint>> m_mapped;

    // Last time something was sent from the socket.
    std::atomic<std::chrono::steady_clock::time_point> m_lastUsed;

    struct StunState
    {
        using HeldPacket = std::pair<PacketBuffer, asio::ip::udp::endpoint>;

        std::mutex mutex;
        // Greater than zero if a STUN binding request was sent and we expect a reply.
        // Counts the number of requests send before the first reply is received.
        unsigned int expectStunResponse = 0;
        // IP address of the STUN server we expect a reply from.
        asio::ip::address expectedStunServer;
        // STUN transaction ID for matching replies with the current request.
        std::array<std::byte, 12> stunTx = {};
        // Packet that must be sent once the address mapping is known.
        std::unique_ptr<HeldPacket> heldPacket;
    } m_stun;

public:
    Socket(asio::io_context& ioCtx, generic::IPEndpoint localEp, bool persistent)
        : m_localEp(localEp)
        , m_persistent(persistent)
        , m_underlay(ioCtx)
    {}

    // Configure STUN for all sockets. Must be called at most once before any
    // sockets are instantiated.
    static void configureStun(bool enable, std::uint16_t port, std::uint32_t timeoutSec);

    const generic::IPEndpoint& local() const { return m_localEp; }

    bool persistent() const { return m_persistent; }

    // Returns the last time something was sent on the socket.
    std::chrono::steady_clock::time_point lastUsed() const { return m_lastUsed.load(); }

    // Check if the underlay socket is open.
    bool isOpen() const { return m_underlay.is_open(); }

    // Open the underlay socket and binds it to the socket's local endpoint.
    // If transparent is set, the socket is created with the IP_TRANSPARENT
    // socket option allowing it to bind to nonlocal IP addresses and to be used
    // with the iptables TPROXY target.
    std::error_code open(bool transparent);

    // Close the underlay socket and cancel all asynchronous operations on it.
    void close()
    {
        m_underlay.close();
    }

#if PERF_DEBUG == 1
    DebugTimestamp lastRx;
#endif

    // Receive and parse a packet.
    asio::awaitable<std::error_code>
    recvPacket(PacketBuffer& pkt, asio::ip::udp::endpoint& from);

    // Send a packet to `nextHop`. Will send a STUN binding request if STUN is
    // enabled and no binding is known or if the binding might be outdated.
    std::error_code sendPacket(PacketBuffer& pkt, const asio::ip::udp::endpoint& nextHop,
        const std::chrono::steady_clock::time_point& t);

private:
    std::error_code respondToBindingReq(
        const PacketBuffer& pkt, const asio::ip::udp::endpoint& from);
    std::error_code requestStunMapping(const PacketBuffer& pkt, asio::ip::udp::endpoint nextHop);
    std::error_code sendHeldPacket();
    void ingressNat(PacketBuffer& pkt, const asio::ip::udp::endpoint& from);
    void egressNat(PacketBuffer& pkt);
};
