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

#include "scion/addr/generic_ip.hpp"
#include "scion/posix/underlay.hpp"

#if _WIN32
#include <ws2tcpip.h>
#define close closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include <optional>


static const char* HOST_NAME = "www.lcschulz.de";

template <typename SockAddrT>
static std::optional<scion::generic::IPAddress> getDefaultAddr(int family)
{
    using namespace scion;

    addrinfo* result;
    addrinfo hints = {};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;

    int err = getaddrinfo(HOST_NAME, "https", &hints, &result);
    if (err != 0) return std::nullopt;

    addrinfo* cur;
    posix::NativeHandle sockfd = -1;
    for (cur = result; cur; cur = cur->ai_next) {
        sockfd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (sockfd < 0) continue;
        if (connect(sockfd, cur->ai_addr, static_cast<socklen_t>(cur->ai_addrlen)) != -1)
            break;
        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(result);
    if (sockfd < 0) return std::nullopt;

    SockAddrT local = {};
    socklen_t len = sizeof(local);
    err = getsockname(sockfd, reinterpret_cast<sockaddr*>(&local), &len);
    close(sockfd);

    if (err < 0) {
        return std::nullopt;
    } else {
        return scion::generic::toGenericAddr(EndpointTraits<SockAddrT>::host(local));
    }
}

namespace scion {
namespace posix {
namespace details {

/// \brief Get a local IPv4 address that was able to connect to the Internet.
std::optional<generic::IPAddress> getDefaultInterfaceAddr4()
{
    static std::optional<generic::IPAddress> def = getDefaultAddr<sockaddr_in>(AF_INET);
    return def;
}

/// \brief Get a local IPv6 address that was able to connect to the Internet.
std::optional<generic::IPAddress> getDefaultInterfaceAddr6()
{
    static std::optional<generic::IPAddress> def = getDefaultAddr<sockaddr_in6>(AF_INET6);
    return def;
}

} // namespace details
} // namespace posix
} // namespace scion
