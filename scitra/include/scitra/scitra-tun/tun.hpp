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


#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

using namespace scion;


class FileDesc
{
private:
    int fd = -1;

public:
    FileDesc() noexcept = default;
    explicit FileDesc(int fd) : fd(fd) {}

    FileDesc(const FileDesc& other) = delete;
    FileDesc(FileDesc&& other) noexcept
        : fd(other.fd)
    {
        other.fd = -1;
    }

    FileDesc& operator=(const FileDesc&) = delete;
    FileDesc& operator=(FileDesc&& other) noexcept
    {
        swap(*this, other);
        return *this;
    }

    friend void swap(FileDesc& a, FileDesc& b)
    {
        std::swap(a.fd, b.fd);
    }

    ~FileDesc() { close(); }

    int get() const { return fd; }
    int release()
    {
        int temp = fd;
        fd = -1;
        return temp;
    }

    const int& operator*() const { return fd; }
    int& operator*() { return fd; }

    void close() noexcept
    {
        if (fd > 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

class CancelEvent
{
private:
    FileDesc event;

public:
    CancelEvent()
    {
        *event = eventfd(0, EFD_NONBLOCK);
        if (*event < 0) {
            throw std::system_error(std::error_code(errno, std::system_category()));
        }
    }

    int get() const { return *event; }

    std::error_code cancel()
    {
        std::uint64_t value = 1;
        if (write(*event, &value, sizeof(value)) < 0) {
            return std::error_code(errno, std::system_category());
        }
        return ErrorCode::Ok;
    }

    void close() noexcept
    {
        event.close();
    }
};

// Represents one queue of a TUN device.
class TunQueue
{
private:
    FileDesc m_queue;
    CancelEvent m_cancel;

public:
    TunQueue(FileDesc&& tun, CancelEvent&& cancel)
        : m_queue(std::move(tun)), m_cancel(std::move(cancel))
    {}

    // Cancel a current or next call to recvPacket().
    std::error_code cancel()
    {
        return m_cancel.cancel();
    }

#if PERF_DEBUG == 1
    DebugTimestamp lastRx;
#endif

    std::error_code recvPacket(scion::scitra::PacketBuffer& pkt)
    {
        pollfd fds[2] = {
            {
                .fd = m_queue.get(),
                .events = POLLIN,
                .revents = 0,
            },
            {
                .fd = m_cancel.get(),
                .events = POLLIN,
                .revents = 0,
            }
        };
        constexpr std::size_t SCION_HEADROOM = 1024;
        auto buffer = pkt.clearAndGetBuffer(SCION_HEADROOM);

        if (poll(fds, sizeof(fds) / sizeof(*fds), -1) < 0) {
            return std::error_code(errno, std::system_category());
        }
        if (fds[1].revents) return ErrorCode::Cancelled;

        auto n = ::read(*m_queue, buffer.data(), buffer.size());
        if (n < 0) return std::error_code(errno, std::system_category());

        DBG_TIME_BEGIN(lastRx);
        if (auto ec = pkt.parsePacket(n, false); ec) {
            return ec;
        }
        return ScitraError::Ok;
    }

    std::error_code sendPacket(scion::scitra::PacketBuffer& pkt)
    {
        auto buffer = pkt.emitPacket(false);
        if (!buffer.has_value()) {
            return buffer.error();
        }

        boost::system::error_code ec;
        auto n = ::write(*m_queue, buffer->data(), buffer->size());
        if (n < 0) return std::error_code(errno, std::system_category());
        if ((std::size_t)n < buffer->size()) return ScitraError::PartialWrite;
        return ScitraError::Ok;
    }
};

// Create a new TUN interface or add another queue to an existing one.
inline Maybe<TunQueue> createTunQueue(std::string& name)
{
    static const char* NET_TUN_PATH = "/dev/net/tun";

    FileDesc q(::open(NET_TUN_PATH, O_RDWR));
    if (*q < 0) {
        throw std::system_error(std::error_code(errno, std::system_category()));
    }

    ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
    if (!name.empty()) {
        auto n = name.size();
        if (n > IFNAMSIZ - 1) {
            throw std::system_error(ScitraError::InvalidArgument);
        }
        std::memcpy(ifr.ifr_name, name.c_str(), n);
    }
    name.assign(ifr.ifr_name);

    if (ioctl(*q, TUNSETIFF, &ifr) < 0) {
        throw std::system_error(std::error_code(errno, std::system_category()));
    }

    if (fcntl(*q, F_SETFL, O_NONBLOCK) < 0) {
        throw std::system_error(std::error_code(errno, std::system_category()));
    }

    return TunQueue(std::move(q), CancelEvent());
}
