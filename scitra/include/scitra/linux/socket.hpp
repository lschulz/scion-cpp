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
#include "scitra/packet.hpp"

#include <boost/asio.hpp>

#include <chrono>
#include <cstdint>

namespace asio = boost::asio;
using namespace scion::scitra;


class Socket
{
private:
    // The local TCP/UDP port number of the socket. Identifies the socket.
    const std::uint16_t localPort;

    // Whether the socket is permanent or temporary.
    const bool m_permanent;

    // Underlay UDP socket for comunicating with SCION routers and hosts.
    asio::ip::udp::socket m_underlay;

    // Last time something was sent from the socket.
    std::chrono::steady_clock::time_point m_lastUsed;

public:
    Socket(asio::io_context& ioCtx, std::uint16_t port, bool permanent)
        : localPort(port)
        , m_permanent(permanent)
        , m_underlay(ioCtx)
    {}

    std::uint16_t port() const { return localPort; }

    bool permanent() const { return m_permanent; }

    std::chrono::steady_clock::time_point lastUsed() const
    {
        return m_lastUsed;
    }

    bool isOpen() const { return m_underlay.is_open(); }

    /// \brief Open the underlay socket and bind it to `bindAddress` on the
    /// network interface `bindDevice`.
    std::error_code open(
        const asio::ip::address& bindAddress, const std::string& bindDevice)
    {
        boost::system::error_code ec;
        m_underlay.open(bindAddress.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
        if (ec) return ec;

        if (!bindDevice.empty()) {
            auto res = ::setsockopt(m_underlay.native_handle(), SOL_SOCKET, SO_BINDTODEVICE,
                bindDevice.c_str(), bindDevice.size() + 1);
            if (res) return std::error_code(errno, std::system_category());
        }

        m_underlay.bind(asio::ip::udp::endpoint(bindAddress, localPort), ec);
        if (ec) return ec;

        return ScitraError::Ok;
    }

    /// \brief Close the underlay socket and cancel all asynchronous operations
    /// on it.
    void close()
    {
        m_underlay.close();
    }

    asio::awaitable<std::error_code> recvPacket(PacketBuffer& pkt, asio::ip::udp::endpoint& from)
    {
        // 4 bytes headroom for the following edge case: A SCION header with an empty path and IPv4
        // host addresses is 4 bytes smaller than the IPv6 header created by the translator.
        constexpr std::size_t IP_HEADROOM = 4;
        auto buffer = pkt.clearAndGetBuffer(IP_HEADROOM);
        constexpr auto token = boost::asio::as_tuple(boost::asio::use_awaitable);
        auto [ec, n] = co_await m_underlay.async_receive_from(asio::buffer(buffer), from, token);
        if (ec) co_return ec;
        ec = pkt.parsePacket(n, true);
        if (ec) co_return ec;
        co_return ScitraError::Ok;
    }

    asio::awaitable<std::error_code>
    sendPacket(PacketBuffer& pkt, const asio::ip::udp::endpoint& nextHop)
    {
        auto buffer = pkt.emitPacket(true);
        if (!buffer.has_value()) {
            co_return buffer.error();
        }
        constexpr auto token = boost::asio::as_tuple(boost::asio::use_awaitable);
        auto [ec, n] = co_await m_underlay.async_send_to(asio::buffer(*buffer), nextHop, token);
        if (ec) co_return ec;
        if (n < buffer->size()) co_return ScitraError::PartialWrite;
        m_lastUsed = std::chrono::steady_clock::now();
        co_return ScitraError::Ok;
    }
};
