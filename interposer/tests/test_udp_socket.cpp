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

#include "interposer.h"
#include "scion/addr/generic_ip.hpp"
#include "scion/addr/mapping.hpp"
#include "scion/details/c_interface.hpp"
#include "scion/posix/sockaddr.hpp"
#include "scion/posix/udp_socket.hpp"
#include "scion/posix/underlay.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"
#include "socket_wrapper.hpp"

#include <vector>


// Bind socket to a SCION-IPv4 address.
TEST(UdpSocket, BindIPv4)
{
    using namespace scion;

    SocketWrapper s(interposer_socket(AF_INET6, SOCK_DGRAM, 0));
    ASSERT_NE(*s, posix::INVALID_SOCKET_VALUE);

    sockaddr_in6 ep1 = EndpointTraits<sockaddr_in6>::fromHostPort(
        unwrap(ScIPAddress::Parse("1-64496,127.0.0.1")
        .and_then(mapToIPv6)
        .and_then([] (const scion::generic::IPAddress& x) {
            return generic::toUnderlay<in6_addr>(x);
        })),
        0
    );
    int err = interposer_bind(*s, reinterpret_cast<sockaddr*>(&ep1), sizeof(ep1));
    ASSERT_EQ(err, 0) << strerror(errno);

    sockaddr_in6 bound;
    socklen_t size = sizeof(bound);
    err = interposer_getsockname(*s, reinterpret_cast<sockaddr*>(&bound), &size);
    ASSERT_EQ(err, 0) << strerror(errno);
    ASSERT_EQ(size, sizeof(bound));
    ASSERT_EQ(bound.sin6_family, AF_INET6);
    ASSERT_NE(bound.sin6_port, 0);
    auto boundIP = generic::IPAddress::MakeIPv6(std::span<const std::byte, 16>(
        reinterpret_cast<const std::byte*>(&bound.sin6_addr), 16));
    ASSERT_TRUE(boundIP.isScion4()) << boundIP;
    auto addr = unmapFromIPv6(boundIP);
    ASSERT_TRUE(addr.has_value());
    ASSERT_EQ(*addr, unwrap(ScIPAddress::Parse("1-64496,127.0.0.1")));
}

// Bind socket to a SCION-IPv6 address via a surrogate address.
TEST(UdpSocket, BindIPv6)
{
    using namespace scion;

    SocketWrapper s(interposer_socket(AF_INET6, SOCK_DGRAM, 0));
    ASSERT_NE(*s, posix::INVALID_SOCKET_VALUE);

    sockaddr_in6 ep1 = EndpointTraits<sockaddr_in6>::fromHostPort(
        unwrap(generic::IPAddress::Parse("fc00::1000")
        .and_then([] (const scion::generic::IPAddress& x) {
            return generic::toUnderlay<in6_addr>(x);
        })),
        0
    );
    int err = interposer_bind(*s, reinterpret_cast<sockaddr*>(&ep1), sizeof(ep1));
    ASSERT_EQ(err, 0) << strerror(errno);

    sockaddr_in6 bound;
    socklen_t size = sizeof(bound);
    err = interposer_getsockname(*s, reinterpret_cast<sockaddr*>(&bound), &size);
    ASSERT_EQ(err, 0) << strerror(errno);
    ASSERT_EQ(size, sizeof(bound));
    ASSERT_EQ(bound.sin6_family, AF_INET6);
    ASSERT_NE(bound.sin6_port, 0);
    auto boundIP = generic::IPAddress::MakeIPv6(std::span<const std::byte, 16>(
        reinterpret_cast<const std::byte*>(&bound.sin6_addr), 16));
    ASSERT_TRUE(boundIP.is6()) << boundIP;
    ASSERT_EQ(boundIP, unwrap(generic::IPAddress::Parse("fc00::1000")));
}

// Promote and unconnected, unbound IPv4 UDP socket to a SCION socket.
// This promotion is only possible if allowPromoteOnSendTo is true.
TEST(UdpSocket, PromoteUnconnectedSocket)
{
    using namespace scion;

    // unconnected IPv4 socket that will be promoted to a SCION socket
    SocketWrapper s(interposer_socket(AF_INET, SOCK_DGRAM, 0));
    ASSERT_NE(*s, posix::INVALID_SOCKET_VALUE);

    // receiving SCION socket
    scion::posix::IpUdpSocket r;
    auto localhost = unwrap(ScIPAddress::Parse("1-64496,0.0.0.0"));
    auto ec = r.bind(ScIPEndpoint(localhost, 0));
    ASSERT_FALSE(ec) << fmtError(ec);

    // Sending to a SCION-mapped address promotes the socket.
    // The destination address is from AF_SCION, as an AF_INET address cannot
    // hold a SCION address.
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto dest = details::endpoint_cast(r.localEp());
    auto sent = interposer_sendto(*s, payload.data(), payload.size(), 0,
        reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
    ASSERT_EQ(sent, (int)payload.size()) << strerror(errno);

    std::vector<std::byte> buffer(1024);
    auto recvd = r.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

// Promote a bound IPv6 UDP socket to a SCION socket.
// This promotion is only possible if allowPromoteOnSendTo is true.
TEST(UdpSocket, PromoteBoundSocket)
{
    using namespace scion;

    // unconnected IPv6 socket that will be promoted to a SCION socket
    SocketWrapper s(interposer_socket(AF_INET6, SOCK_DGRAM, 0));
    ASSERT_NE(*s, posix::INVALID_SOCKET_VALUE);

    // bind the socket to a non-SCION address
    sockaddr_in6 bind = {};
    bind.sin6_family = AF_INET6;
    bind.sin6_addr = unwrap(AddressTraits<in6_addr>::fromString("::1"));
    bind.sin6_port = details::byteswapBE<std::uint16_t>(31100);
    int res = interposer_bind(*s, reinterpret_cast<sockaddr*>(&bind), sizeof(bind));
    ASSERT_EQ(res, 0) << strerror(errno);

    // receiving SCION socket
    scion::posix::IpUdpSocket r;
    auto localhost = unwrap(ScIPAddress::Parse("1-64496,::0"));
    auto underlay = unwrap(AddressTraits<scion::posix::IPAddress>::fromString("::1"));
    auto ec = r.bind(ScIPEndpoint(localhost, 31101), &underlay);
    ASSERT_FALSE(ec) << fmtError(ec);

    // Sending to a SCION-mapped address promotes the socket.
    // Destination address is a surrogate IP, as sending to a SCION-mapped IPv6
    // would require that address to actually exist in the OS.
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    sockaddr_in6 dest = {};
    dest.sin6_family = AF_INET6;
    dest.sin6_addr = unwrap(AddressTraits<in6_addr>::fromString("fc00::1000"));
    dest.sin6_port = details::byteswapBE<std::uint16_t>(31101);
    auto sent = interposer_sendto(*s, payload.data(), payload.size(), 0,
        reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
    ASSERT_EQ(sent, (int)payload.size()) << strerror(errno);

    std::vector<std::byte> buffer(1024);
    auto recvd = r.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

class UdpSocketFixture : public testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        using namespace std::chrono_literals;

        auto sock1 = SocketWrapper(interposer_socket(AF_SCION, SOCK_DGRAM, 0));
        ASSERT_NE(*sock1, posix::INVALID_SOCKET_VALUE);

        auto localhost = unwrap(ScIPAddress::Parse("1-64496,127.0.0.1"));
        auto ep1 = details::endpoint_cast(ScIPEndpoint(localhost, 0));
        int err = interposer_bind(*sock1, reinterpret_cast<sockaddr*>(&ep1), sizeof(ep1));
        ASSERT_EQ(err, 0) << strerror(errno);

        socklen_t size = sizeof(ep1);
        err = interposer_getsockname(*sock1, reinterpret_cast<sockaddr*>(&ep1), &size);
        ASSERT_EQ(err, 0) << strerror(errno);
        ASSERT_EQ(size, sizeof(ep1));
        nativeEp = details::endpoint_cast(&ep1);

        scion::posix::IpUdpSocket sock2;
        auto ec = sock2.bind(ScIPEndpoint(localhost, 0));
        ASSERT_FALSE(ec) << fmtError(ec);

        ec = sock2.connect(ScIPEndpoint(localhost, details::byteswapBE(ep1.sscion_port)));
        ASSERT_FALSE(ec) << fmtError(ec);

        scionEp = sock2.localEp();
        sockaddr_scion ep2 = details::endpoint_cast(scionEp);
        err = interposer_connect(*sock1, reinterpret_cast<sockaddr*>(&ep2), sizeof(ep2));
        ASSERT_EQ(err, 0) << strerror(errno);

    #if _WIN32
        DWORD t = 1000;
        ASSERT_FALSE(setsockopt(*sock1, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&t), sizeof(t)));
    #else
        struct timeval t = {.tv_sec = 1, .tv_usec = 0};
        ASSERT_FALSE(setsockopt(*sock1, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&t), sizeof(t)));
    #endif
        sock2.setRecvTimeout(1s);

        nativeSocket = std::move(sock1);
        scionSocket = std::move(sock2);
    }

    static void TearDownTestSuite()
    {
        nativeSocket.close();
        scionSocket.close();
    }

    inline static scion::ScIPEndpoint nativeEp;
    inline static scion::ScIPEndpoint scionEp;
    inline static SocketWrapper nativeSocket;
    inline static scion::posix::IpUdpSocket scionSocket;
};

TEST_F(UdpSocketFixture, Read)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto nh = unwrap(toUnderlay<posix::IpUdpSocket::UnderlayEp>(nativeEp.localEp()));
    ASSERT_FALSE(isError(scionSocket.send(headers, RawPath(), nh, payload)));

    std::vector<std::byte> buffer(1024);
    auto read = interposer_read(*nativeSocket, buffer.data(), buffer.size());
    ASSERT_EQ(read, (int)payload.size());
    buffer.resize(read);
    ASSERT_THAT(buffer, testing::ElementsAreArray(payload));
}

TEST_F(UdpSocketFixture, Recv)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    // Nonblocking receive
    std::vector<std::byte> buffer(1024);
    auto recvd = interposer_recv(*nativeSocket, buffer.data(), buffer.size(), MSG_DONTWAIT);
    ASSERT_EQ(recvd, -1);
    ASSERT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);

    // Send a datagram to the socket
    auto nh = unwrap(toUnderlay<posix::IpUdpSocket::UnderlayEp>(nativeEp.localEp()));
    ASSERT_FALSE(isError(scionSocket.send(headers, RawPath(), nh, payload)));

    // Peek at receive queue
    recvd = interposer_recv(*nativeSocket, buffer.data(), buffer.size(), MSG_PEEK);
    ASSERT_EQ(recvd, (int)payload.size());
    buffer.resize(recvd);
    ASSERT_THAT(buffer, testing::ElementsAreArray(payload));

    // Receive and remove from queue
    buffer.resize(1024);
    recvd = interposer_recv(*nativeSocket, buffer.data(), buffer.size(), 0);
    ASSERT_EQ(recvd, (int)payload.size());
    buffer.resize(recvd);
    ASSERT_THAT(buffer, testing::ElementsAreArray(payload));
}

// Test recv with MSG_TRUNC flag.
TEST_F(UdpSocketFixture, RecvTruncate)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    // Send a datagram to the socket
    auto nh = unwrap(toUnderlay<posix::IpUdpSocket::UnderlayEp>(nativeEp.localEp()));
    ASSERT_FALSE(isError(scionSocket.send(headers, RawPath(), nh, payload)));

    // Buffer too small, but without MSG_TRUNC
    std::vector<std::byte> buffer(4);
    auto recvd = interposer_recv(*nativeSocket, buffer.data(), buffer.size(), MSG_PEEK);
    ASSERT_EQ(recvd, 4);
    ASSERT_THAT(buffer, testing::ElementsAre(1_b, 2_b, 3_b, 4_b));

    // With MSG_TRUNC
    recvd = interposer_recv(*nativeSocket, buffer.data(), buffer.size(), MSG_TRUNC);
    ASSERT_EQ(recvd, 8);
    ASSERT_THAT(buffer, testing::ElementsAre(1_b, 2_b, 3_b, 4_b));
}

TEST_F(UdpSocketFixture, RecvFrom)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto nh = unwrap(toUnderlay<posix::IpUdpSocket::UnderlayEp>(nativeEp.localEp()));
    ASSERT_FALSE(isError(scionSocket.send(headers, RawPath(), nh, payload)));

    std::vector<std::byte> buffer(1024);
    sockaddr_storage from;
    socklen_t fromLen = sizeof(from);
    auto recvd = interposer_recvfrom(*nativeSocket, buffer.data(), buffer.size(), 0,
        reinterpret_cast<sockaddr*>(&from), &fromLen);
    ASSERT_EQ(recvd, (int)payload.size());
    buffer.resize(recvd);
    ASSERT_THAT(buffer, testing::ElementsAreArray(payload));
    ASSERT_EQ(from.ss_family, AF_SCION);
    ASSERT_EQ(fromLen, sizeof(sockaddr_scion));
    auto* sa = reinterpret_cast<sockaddr_scion*>(&from);
    EXPECT_EQ(sa->sscion_addr.sscion_isd_asn, scion_htonll((1ull << 48 )| 64496ull));
    EXPECT_EQ(sa->sscion_addr.sscion_host_type, SCION_IPv4);
    EXPECT_EQ(sa->sscion_addr.sscion_scope_id, 0);
    EXPECT_THAT(sa->sscion_addr.u.sscion_addr, testing::ElementsAre(
        127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ));
    EXPECT_EQ(details::byteswapBE(sa->sscion_port), scionEp.port());
}

TEST_F(UdpSocketFixture, RecvMsg)
{
    using namespace scion;
    using namespace std::ranges;

    HeaderCache headers;
    std::vector<std::byte> payload(1024);
    generate(payload, [] () -> std::byte {
        return std::byte{(std::uint8_t)std::rand()};
    });

    auto nh = unwrap(toUnderlay<posix::IpUdpSocket::UnderlayEp>(nativeEp.localEp()));
    ASSERT_FALSE(isError(scionSocket.send(headers, RawPath(), nh, payload)));

    sockaddr_storage from;
    std::array<std::vector<std::byte>, 3> buffers;
    std::vector<iovec> iovecs;
    iovecs.reserve(buffers.size());
    for (auto& buffer : buffers) {
        buffer.resize(500);
        iovecs.push_back(iovec{
            .iov_base = buffer.data(),
            .iov_len = buffer.size(),
        });
    }
    msghdr msg = {};
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = iovecs.data();
    msg.msg_iovlen = iovecs.size();

    auto recvd = interposer_recvmsg(*nativeSocket, &msg, 0);
    ASSERT_EQ(recvd, (int)payload.size());
    ASSERT_TRUE(equal(buffers[0], take_view(payload, 500)));
    ASSERT_TRUE(equal(buffers[1], take_view(drop_view(payload, 500), 500)));
    ASSERT_TRUE(equal(take_view(buffers[2], 24), take_view(drop_view(payload, 1000), 24)));
}

TEST_F(UdpSocketFixture, Write)
{
    using namespace scion;

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto written = interposer_write(*nativeSocket, payload.data(), payload.size());
    ASSERT_EQ(written, (int)payload.size()) << strerror(errno);

    std::vector<std::byte> buffer(1024);
    auto recvd = scionSocket.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(UdpSocketFixture, Send)
{
    using namespace scion;

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto sent = interposer_send(*nativeSocket, payload.data(), payload.size(), 0);
    ASSERT_EQ(sent, (int)payload.size()) << strerror(errno);

    std::vector<std::byte> buffer(1024);
    auto recvd = scionSocket.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

// Test sendto with SCION destination address.
TEST_F(UdpSocketFixture, SendTo)
{
    using namespace scion;

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto dest = details::endpoint_cast(scionEp);
    auto sent = interposer_sendto(*nativeSocket, payload.data(), payload.size(), 0,
        reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
    ASSERT_EQ(sent, (int)payload.size()) << strerror(errno);

    std::vector<std::byte> buffer(1024);
    auto recvd = scionSocket.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

// Test sendto with SCION-mapped IPv6 destination address.
TEST_F(UdpSocketFixture, SendToMapped)
{
    using namespace scion;

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    sockaddr_in6 dest = {};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = details::byteswapBE(scionEp.port());
    auto mapped = unwrap(mapToIPv6(scionEp.address()));
    mapped.toBytes16(std::span<std::byte, 16>(
        reinterpret_cast<std::byte*>(&dest.sin6_addr), 16));

    auto sent = interposer_sendto(*nativeSocket, payload.data(), payload.size(), 0,
        reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
    ASSERT_EQ(sent, (int)payload.size()) << strerror(errno);

    std::vector<std::byte> buffer(1024);
    auto recvd = scionSocket.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(UdpSocketFixture, SendMsg)
{
    using namespace scion;
    using namespace std::ranges;

    std::array<std::vector<std::byte>, 3> payload;
    std::vector<iovec> iovecs;
    iovecs.reserve(payload.size());
    for (auto& buffer : payload) {
        buffer.resize(300);
        generate(buffer, [] () -> std::byte {
            return std::byte{(std::uint8_t)std::rand()};
        });
        iovecs.push_back(iovec{
            .iov_base = buffer.data(),
            .iov_len = buffer.size(),
        });
    }
    msghdr msg = {};
    msg.msg_iov = iovecs.data();
    msg.msg_iovlen = iovecs.size();

    auto sent = interposer_sendmsg(*nativeSocket, &msg, 0);
    ASSERT_EQ(sent, 900) << strerror(errno);

    std::vector<std::byte> buffer(1024);
    auto recvd = scionSocket.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_TRUE(equal(take_view(*recvd, 300), payload[0]));
    ASSERT_TRUE(equal(take_view(drop_view(*recvd, 300), 300), payload[1]));
    ASSERT_TRUE(equal(take_view(drop_view(*recvd, 600), 300), payload[2]));
}

#if _GNU_SOURCE

TEST_F(UdpSocketFixture, RecvMMsg)
{
    using namespace scion;
    using namespace std::ranges;

    std::array<std::vector<std::byte>, 3> payload;
    std::array<iovec, 3> iovecs = {};
    std::array<mmsghdr, 3> msgs = {};
    for (int i = 0; i < 3; ++i) {
        payload[i].resize(500);
        generate(payload[i], [] () -> std::byte {
            return std::byte{(std::uint8_t)std::rand()};
        });
        iovecs[i].iov_base = payload[i].data();;
        iovecs[i].iov_len = payload[i].size();
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    auto res = interposer_sendmmsg(*nativeSocket, msgs.data(), msgs.size(), 0);
    ASSERT_EQ(res, 3) << strerror(errno);
    ASSERT_EQ(msgs[0].msg_len, 500);
    ASSERT_EQ(msgs[1].msg_len, 500);
    ASSERT_EQ(msgs[2].msg_len, 500);

    std::vector<std::byte> buffer(1024);
    for (int i = 0; i < 3; ++i) {
        auto recvd = scionSocket.recv(buffer);
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_TRUE(equal(*recvd, payload[i]));
    }
}

TEST_F(UdpSocketFixture, SendMMsg)
{
    using namespace scion;
    using namespace std::ranges;

    HeaderCache headers;
    std::array<std::vector<std::byte>, 3> payload;
    for (int i = 0; i < 3; ++i) {
        payload[i].resize(500);
        generate(payload[i], [] () -> std::byte {
            return std::byte{(std::uint8_t)std::rand()};
        });
    }

    auto nh = unwrap(toUnderlay<posix::IpUdpSocket::UnderlayEp>(nativeEp.localEp()));
    for (int i = 0; i < 3; ++i) {
        ASSERT_FALSE(isError(scionSocket.send(headers, RawPath(), nh, payload[i])));
    }

    std::array<std::vector<std::byte>, 3> buffers;
    std::array<iovec, 3> iovecs = {};
    std::array<mmsghdr, 3> msgs = {};
    for (int i = 0; i < 3; ++i) {
        buffers[i].resize(1024);
        iovecs[i].iov_base = buffers[i].data();;
        iovecs[i].iov_len = buffers[i].size();
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    auto res = interposer_recvmmsg(*nativeSocket, msgs.data(), msgs.size(), 0, nullptr);
    ASSERT_EQ(res, 3) << strerror(errno);
    ASSERT_EQ(msgs[0].msg_len, 500);
    ASSERT_EQ(msgs[1].msg_len, 500);
    ASSERT_EQ(msgs[2].msg_len, 500);
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(equal(take_view(buffers[i], 500), payload[i]));
    }
}

TEST_F(UdpSocketFixture, SockoptPathMTU)
{
    int mtu = 0;
    socklen_t len = sizeof(mtu);
    ASSERT_EQ(interposer_getsockopt(*nativeSocket, IPPROTO_IPV6, IPV6_MTU, &mtu, &len), 0);
    EXPECT_EQ(mtu, 1400);
}

#endif // _GNU_SOURCE
