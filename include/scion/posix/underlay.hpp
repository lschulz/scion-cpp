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
#include "scion/posix/sockaddr.hpp"

#if _WIN32
#include <Winsock2.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#include <array>
#include <cstdint>
#include <optional>
#include <span>


namespace scion {
namespace posix {

#if _WIN32
using NativeHandle = SOCKET;
constexpr NativeHandle INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
using NativeHandle = int;
constexpr NativeHandle INVALID_SOCKET_VALUE = -1;
#endif

namespace details {
inline std::error_code getLastError()
{
#if _WIN32
    return std::error_code(WSAGetLastError(), std::system_category());
#else
    return std::error_code(errno, std::system_category());
#endif
}
} // namespace details

/// \brief Thin wrapper around a POSIX datagram socket.
/// \tparam T A sockaddr, like sockaddr_in or sockaddr_in6.
template <typename T = IPEndpoint>
class PosixSocket
{
public:
    static_assert(std::is_standard_layout_v<T>);
    using SockAddr = T;

private:
    NativeHandle handle = INVALID_SOCKET_VALUE;

public:
    PosixSocket() noexcept = default;

    /// \brief Adopt a socket handle.
    explicit PosixSocket(NativeHandle socket)
        : handle(socket)
    {}

    PosixSocket(const PosixSocket&) noexcept = delete;
    PosixSocket(PosixSocket&& other) noexcept
        : handle(other.handle)
    {
        other.handle = INVALID_SOCKET_VALUE;
    }

    PosixSocket& operator=(const PosixSocket&) noexcept = delete;
    PosixSocket& operator=(PosixSocket&& other) noexcept
    {
        swap(*this, other);
        return *this;
    }

    friend void swap(PosixSocket& a, PosixSocket& b)
    {
        std::swap(a.handle, b.handle);
    }

    ~PosixSocket()
    {
        close();
    }

    /// \brief Determine whether the socket is open.
    bool isOpen() const { return handle != INVALID_SOCKET_VALUE; }

    /// \brief Get the native socket handle.
    NativeHandle underlaySocket() { return handle; }

    NativeHandle release()
    {
        auto h = handle;
        handle = INVALID_SOCKET_VALUE;
        return h;
    }

    std::error_code bind(const SockAddr& addr)
    {
        if (handle == INVALID_SOCKET_VALUE) {
            auto ec = create(addr);
            if (ec) return ec;
        }
        if (::bind(handle, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr))) {
            return details::getLastError();
        }
        return ErrorCode::Ok;
    }

    /// \brief Bind the socket to a local endpoint. If `addr` does not specify a
    /// port, try to pick one from the range [`firstPort`, `lastPort`].
    std::error_code bind_range(
        const SockAddr& addr, std::uint16_t firstPort, std::uint16_t lastPort)
    {
        if (firstPort > lastPort) return std::make_error_code(std::errc::address_in_use);
        if (firstPort == 0 && lastPort == 65535)
            return bind(addr);

        auto ip = EndpointTraits<SockAddr>::host(addr);
        auto port = EndpointTraits<SockAddr>::port(addr);
        if (port != 0) return bind(addr);

        if (handle == INVALID_SOCKET_VALUE) {
            auto ec = create(addr);
            if (ec) return ec;
        }

        for (int tryPort = lastPort; tryPort >= firstPort; tryPort--) {
            auto sa = EndpointTraits<SockAddr>::fromHostPort(ip, (std::uint16_t)tryPort);
            if (::bind(handle, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) == 0) {
                return ErrorCode::Ok;
            } else {
            #if _WIN32
                int error = WSAGetLastError();
                if (error == WSAEADDRINUSE || error == WSAEACCES)
                    continue;
                else
                    return details::getLastError();
            #else
                if (errno == EADDRINUSE)
                    continue;
                else
                    return details::getLastError();
            #endif
            }
        }
        return std::make_error_code(std::errc::address_in_use);
    }

    std::error_code connect(const SockAddr& addr)
    {
        if (handle == INVALID_SOCKET_VALUE) {
            auto ec = create(addr);
            if (ec) return ec;
        }
        if (::connect(handle, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr))) {
            return details::getLastError();
        }
        return ErrorCode::Ok;
    }

    void close()
    {
        if (handle >= 0) {
        #if _WIN32
            closesocket(handle);
        #else
            ::close(handle);
        #endif
            handle = INVALID_SOCKET_VALUE;
        }
    }

    /// \brief Set the socket to nonblocking or blocking mode. Sockets always
    /// start in blocking mode, but can be switched to nonblocking.
    /// \note On Windows, a nonblocking socket cannot be returned to blocking
    /// operation after WSAAsyncSelect() or WSAEventSelect() have been called on
    /// the socket. WSAAsyncSelect() and WSAEventSelect() automatically switch
    /// the socket to non-blocking mode when first called.
    std::error_code setNonblocking(bool nonblocking)
    {
    #if _WIN32
        unsigned long mode = nonblocking;
        if (ioctlsocket(handle, FIONBIO, &mode))
            return details::getLastError();
        return ErrorCode::Ok;
    #else
        int flags = fcntl(handle, F_GETFL, 0);
        if (flags == -1) return details::getLastError();
        if (nonblocking)
            flags |= O_NONBLOCK;
        else
            flags &= ~O_NONBLOCK;
        if (fcntl(handle, F_SETFL, flags) == -1)
            return details::getLastError();
        return ErrorCode::Ok;
    #endif
    }

    Maybe<SockAddr> getsockname() const
    {
        SockAddr addr = {};
        socklen_t addrLen = sizeof(addr);
        if (::getsockname(handle, reinterpret_cast<sockaddr*>(&addr), &addrLen) == -1) {
            return Error(details::getLastError());
        }
        return addr;
    }

    std::error_code getsockopt(int level, int optname, void* optval, socklen_t* optlen)
    {
    #if _WIN32
        auto optvalChar = reinterpret_cast<const char*>(optval);
        if (::getsockopt(handle, level, optname, optvalChar, optlen) == SOCKET_ERROR) {
            return details::getLastError();
        }
    #else
        if (::getsockopt(handle, level, optname, optval, optlen) == -1) {
            return details::getLastError();
        }
    #endif
        return std::error_code(0, std::system_category());
    }

    std::error_code setsockopt(int level, int optname, const void* optval, socklen_t optlen)
    {
    #if _WIN32
        auto optvalChar = reinterpret_cast<const char*>(optval);
        if (::setsockopt(handle, level, optname, optvalChar, optlen) == SOCKET_ERROR) {
            return details::getLastError();
        }
    #else
        if (::setsockopt(handle, level, optname, optval, optlen) == -1) {
            return details::getLastError();
        }
    #endif
        return std::error_code(0, std::system_category());
    }

    Maybe<std::span<const std::byte>> send(std::span<const std::byte> buf, int flags = 0)
    {
        auto n = ::send(handle,
            reinterpret_cast<const char*>(buf.data()), static_cast<socklen_t>(buf.size()), 0);
        if (n < 0) return Error(details::getLastError());
        return buf.subspan(0, n);
    }

    Maybe<std::span<const std::byte>> sendto(
        std::span<const std::byte> buf, const SockAddr& to, int flags = 0)
    {
        auto n = ::sendto(handle,
            reinterpret_cast<const char*>(buf.data()), static_cast<socklen_t>(buf.size()), flags,
            reinterpret_cast<const sockaddr*>(&to), sizeof(to));
        if (n < 0) return Error(details::getLastError());
        return buf.subspan(0, n);
    }

#if __linux__
    template <std::convertible_to<std::span<const std::byte>>... Buffers>
    Maybe<ssize_t> sendmsg(const SockAddr& to, int flags, Buffers&&... bufs)
    {
        auto make_iovec = [](const auto& buf) {
            return iovec {
                .iov_base = const_cast<void*>(reinterpret_cast<const void*>(buf.data())),
                .iov_len = buf.size(),
            };
        };
        std::array<iovec, sizeof...(Buffers)> vec = {make_iovec(bufs)...};
        msghdr hdr{
            .msg_name = const_cast<sockaddr*>(reinterpret_cast<const sockaddr*>(&to)),
            .msg_namelen = sizeof(to),
            .msg_iov = vec.data(),
            .msg_iovlen = vec.size(),
            .msg_control = NULL,
            .msg_controllen = 0,
            .msg_flags = 0,
        };
        auto n = ::sendmsg(handle, &hdr, flags);
        if (n < 0) return Error(details::getLastError());
        return n;
    }
#endif
#if _WIN32
    template <std::convertible_to<std::span<const std::byte>>... Buffers>
    Maybe<DWORD> sendmsg(const SockAddr& to, int flags, Buffers&&... bufs)
    {
        auto make_wsabuf = [](const auto& buf) {
            return WSABUF {
                .len = static_cast<ULONG>(buf.size()),
                .buf = const_cast<char*>(reinterpret_cast<const char*>(buf.data())),
            };
        };
        std::array<WSABUF, sizeof...(Buffers)> vec = {make_wsabuf(bufs)...};
        WSAMSG msg{
            .name = const_cast<sockaddr*>(reinterpret_cast<const sockaddr*>(&to)),
            .namelen = sizeof(to),
            .lpBuffers = vec.data(),
            .dwBufferCount = (ULONG)vec.size(),
            .Control = {},
            .dwFlags = 0,
        };
        DWORD n = 0;
        if (WSASendMsg(handle, &msg, 0, &n, nullptr, nullptr)) {
            return Error(details::getLastError());
        }
        return n;
    }
#endif

    Maybe<std::span<std::byte>> recv(std::span<std::byte> buf, int flags = 0)
    {
    #if _WIN32
        auto n = ::recv(handle,
            reinterpret_cast<char*>(buf.data()), static_cast<socklen_t>(buf.size()), flags);
        if (n < 0) {
            int error = WSAGetLastError();
            if (error == WSAEMSGSIZE) return Error(ErrorCode::BufferTooSmall);
            return std::error_code(error, std::system_category());
        }
        return buf.subspan(0, n);
    #else
        long n = 0;
        do {
            n = ::recv(handle, buf.data(), buf.size(), flags | MSG_TRUNC);
        } while (n < 0 && errno == EINTR);
        if (n < 0) return Error(details::getLastError());
        if ((std::size_t)n > buf.size()) return Error(ErrorCode::BufferTooSmall);
        return buf.subspan(0, n);
    #endif
    }

    Maybe<std::span<std::byte>> recvfrom(std::span<std::byte> buf, SockAddr& from, int flags = 0)
    {
    #if _WIN32
        int addrLen = static_cast<int>(sizeof(from));
        auto n = ::recvfrom(handle,
            reinterpret_cast<char*>(buf.data()), static_cast<socklen_t>(buf.size()), flags,
            reinterpret_cast<sockaddr*>(&from), &addrLen);
        if (n < 0) {
            int error = WSAGetLastError();
            if (error == WSAEMSGSIZE) return Error(ErrorCode::BufferTooSmall);
            return Error(details::getLastError());
        }
        return buf.subspan(0, n);
    #else
        long n = 0;
        socklen_t addrLen = sizeof(from);
        do {
            n = ::recvfrom(handle, buf.data(), buf.size(), flags | MSG_TRUNC,
                reinterpret_cast<sockaddr*>(&from), &addrLen);
        } while (n < 0 && errno == EINTR);
        if (n < 0) return Error(details::getLastError());
        if ((std::size_t)n > buf.size()) return Error(ErrorCode::BufferTooSmall);
        return buf.subspan(0, n);
    #endif
    }

private:
    std::error_code create(const SockAddr& addr)
    {
        auto family = reinterpret_cast<const sockaddr*>(&addr)->sa_family;
        handle = ::socket(family, SOCK_DGRAM, 0);
        if (handle < 0) return details::getLastError();
        return ErrorCode::Ok;
    }
};

namespace details
{
std::optional<generic::IPAddress> getDefaultInterfaceAddr4();
std::optional<generic::IPAddress> getDefaultInterfaceAddr6();

/// \brief Get the address the socket is bound to or in case it is bound to a
/// wildcard address, an arbitrary local address.
template <typename Sockaddr>
Maybe<generic::IPEndpoint> findLocalAddress(const posix::PosixSocket<Sockaddr>& s)
{
    using IPAddress = typename EndpointTraits<Sockaddr>::HostAddr;
    auto bound = s.getsockname();
    if (isError(bound)) return propagateError(bound);
    auto ip = EndpointTraits<Sockaddr>::host(*bound);
    auto port = EndpointTraits<Sockaddr>::port(*bound);
    generic::IPAddress localAddr;
    if (AddressTraits<IPAddress>::isUnspecified(ip)) {
        std::optional<generic::IPAddress> defAddr;
        if (AddressTraits<IPAddress>::type(ip) == HostAddrType::IPv4
            || AddressTraits<IPAddress>::is4in6(ip))
            defAddr = getDefaultInterfaceAddr4();
        else
            defAddr = getDefaultInterfaceAddr6();
        if (!defAddr) return Error(ErrorCode::NoLocalHostAddr);
            localAddr = defAddr.value();
    } else {
        localAddr = generic::toGenericAddr(ip);
    }
    return generic::IPEndpoint(localAddr, port);
}
} // namespace details

} // namespace posix
} // namespace scion
