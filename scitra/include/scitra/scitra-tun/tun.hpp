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

#if __INTELLISENSE__
#define BOOST_ASIO_HAS_IO_URING 1
#endif
#include <boost/asio.hpp>

#include <linux/if_tun.h>
#include <linux/if.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace asio = boost::asio;
using namespace scion;


using AsyncFile = asio::basic_stream_file<typename asio::io_context::executor_type>;

/// \brief Create a new TUN interface or add another queue to an existing one.
inline Maybe<AsyncFile> createTunQueue(asio::io_context& ctx, std::string& name)
{
    static const char* NET_TUN_PATH = "/dev/net/tun";

    AsyncFile tun(ctx, ::open(NET_TUN_PATH, O_RDWR));
    if (!tun.is_open()) {
        return Error(std::error_code(errno, std::system_category()));
    }

    ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    if (!name.empty()) {
        auto n = name.size();
        if (n > IFNAMSIZ - 1) {
            return Error(ScitraError::InvalidArgument);
        }
        std::memcpy(ifr.ifr_name, name.c_str(), n);
    }

    if (ioctl(tun.native_handle(), TUNSETIFF, &ifr) < 0) {
        return Error(std::error_code(errno, std::system_category()));
    }

    name.assign(ifr.ifr_name);
    return tun;
}

/// \brief Represents one queue of a TUN device.
class TunQueue
{
private:
    AsyncFile m_queue;

public:
    explicit TunQueue(AsyncFile&& tun)
        : m_queue(std::move(tun))
    {}

    bool isOpen() const { return m_queue.is_open(); }

    void close() { m_queue.close(); }

#ifndef NNPERF_DEBUG
    DebugTimestamp lastRx;
#endif

    asio::awaitable<std::error_code>
    recvPacket(scion::scitra::PacketBuffer& pkt)
    {
        constexpr std::size_t SCION_HEADROOM = 1024;
        auto buffer = pkt.clearAndGetBuffer(SCION_HEADROOM);
        constexpr auto token = asio::as_tuple(asio::use_awaitable);
        auto [ec, n] = co_await m_queue.async_read_some(asio::buffer(buffer), token);
        if (ec) co_return ec;
        DBG_TIME_BEGIN(lastRx);

        if (auto ec = pkt.parsePacket(n, false); ec) {
            co_return ec;
        }
        co_return ScitraError::Ok;
    }

    asio::awaitable<std::error_code>
    sendPacket(scion::scitra::PacketBuffer& pkt)
    {
        auto buffer = pkt.emitPacket(false);
        if (!buffer.has_value()) {
            co_return buffer.error();
        }

        constexpr auto token = asio::as_tuple(asio::use_awaitable);
        auto [ec, n] = co_await m_queue.async_write_some(asio::buffer(*buffer), token);
        if (n < buffer->size()) co_return ScitraError::PartialWrite;
        co_return ScitraError::Ok;
    }
};
