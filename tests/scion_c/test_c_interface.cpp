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

#include "scion/scion.h"
#include "scion/details/c_interface.hpp"

#include "scion/addr/isd_asn.hpp"
#include "scion/addr/address.hpp"
#include "scion/addr/endpoint.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/bit_stream.hpp"
#include "scion/details/bit.hpp"
#include "scion/path/path.hpp"
#include "scion/daemon/client.hpp"
#include "scion/posix/sockaddr.hpp"
#include "scion/posix/udp_socket.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <cstddef>
#include <ranges>

using std::uint16_t;
using std::uint64_t;
using std::size_t;


static bool operator==(const scion_hop& a, const scion_hop& b)
{
    return a.isd_asn == b.isd_asn && a.ingress == b.ingress && a.egress == b.egress;
}

TEST(CInterface, ScionAddress)
{
    using namespace scion;

    scion_addr addr = SCIONADDR_ANY4_INIT();
    EXPECT_EQ(addr.sscion_host_type, SCION_IPv4);
    EXPECT_TRUE(SCION_IS_ADDR_UNSPECIFIED(&addr));

    addr = SCIONADDR_ANY6_INIT();
    EXPECT_EQ(addr.sscion_host_type, SCION_IPv6);
    EXPECT_TRUE(SCION_IS_ADDR_UNSPECIFIED(&addr));

    IsdAsn isdAsn(Isd(1), Asn(0xff00'abcd'ffff));
    auto ia = SCION_ISD_ASN((uint16_t)isdAsn.isd(), (uint64_t)isdAsn.asn());
    EXPECT_EQ(Isd(SCION_ISD_ASN_GET_ISD(ia)), isdAsn.isd());
    EXPECT_EQ(Asn(SCION_ISD_ASN_GET_ASN(ia)), isdAsn.asn());

    std::uint64_t n = 0;
    std::array<std::byte, sizeof(n)> buffer;
    WriteStream ws(buffer);
    ASSERT_TRUE(isdAsn.serialize(ws, NullStreamError));

    std::ranges::copy(buffer, reinterpret_cast<std::byte*>(&n));
    EXPECT_EQ(ia, n);
}

TEST(CInterface, ScionAddressTextIO)
{
    using namespace scion;

    scion_addr addr;
    EXPECT_EQ(scion_parse_host("::1", &addr), SCION_SYNTAX_ERROR);
    EXPECT_EQ(scion_parse_host("1-ff00:0:0,::1", &addr), SCION_OK);
    EXPECT_EQ(addr.sscion_host_type, SCION_IPv6);
    EXPECT_EQ(scion_ntohll(addr.sscion_isd_asn), unwrap(IsdAsn::Parse("1-ff00:0:0")));
    EXPECT_EQ(addr.sscion_scope_id, 0);
    EXPECT_THAT(addr.u.sscion_addr32, testing::ElementsAre(
        0, 0, 0, htonl(1)
    ));

    std::string buffer;
    buffer.resize(16);
    size_t len = 0;
    EXPECT_EQ(scion_print_host(&addr, buffer.data(), &len), SCION_BUFFER_TOO_SMALL);
    EXPECT_EQ(len, 15);
    len = 10;
    EXPECT_EQ(scion_print_host(&addr, buffer.data(), &len), SCION_BUFFER_TOO_SMALL);
    EXPECT_EQ(len, 15);
    len = buffer.size();
    EXPECT_EQ(scion_print_host(&addr, buffer.data(), &len), SCION_OK);
    ASSERT_EQ(len, 15);
    buffer.resize(len - 1);
    EXPECT_EQ(buffer, "1-ff00:0:0,::1");
}

TEST(CInterface, ScionSockaddrTextIO)
{
    using namespace scion;

    sockaddr_scion sa;
    EXPECT_EQ(scion_parse_ep("[::1],1024", &sa), SCION_SYNTAX_ERROR);
    EXPECT_EQ(scion_parse_ep("[1-ff00:0:0,::1]:1024", &sa), SCION_OK);
    EXPECT_EQ(sa.sscion_family, AF_SCION);
    EXPECT_EQ(sa.sscion_flowinfo, 0);
    EXPECT_EQ(sa.sscion_port, htons(1024));
    EXPECT_EQ(sa.sscion_addr.sscion_host_type, SCION_IPv6);
    EXPECT_EQ(scion_ntohll(sa.sscion_addr.sscion_isd_asn), unwrap(IsdAsn::Parse("1-ff00:0:0")));
    EXPECT_EQ(sa.sscion_addr.sscion_scope_id, 0);
    EXPECT_THAT(sa.sscion_addr.u.sscion_addr32, testing::ElementsAre(
        0, 0, 0, htonl(1)
    ));

    std::string buffer;
    buffer.resize(23);
    size_t len = 0;
    EXPECT_EQ(scion_print_ep(&sa, buffer.data(), &len), SCION_BUFFER_TOO_SMALL);
    EXPECT_EQ(len, 22);
    len = 10;
    EXPECT_EQ(scion_print_ep(&sa, buffer.data(), &len), SCION_BUFFER_TOO_SMALL);
    EXPECT_EQ(len, 22);
    len = buffer.size();
    EXPECT_EQ(scion_print_ep(&sa, buffer.data(), &len), SCION_OK);
    ASSERT_EQ(len, 22);
    buffer.resize(len - 1);
    EXPECT_EQ(buffer, "[1-ff00:0:0,::1]:1024");
}

class CInterfaceFixture : public testing::Test
{
protected:
    using Socket = scion::posix::UdpSocket<scion::posix::PosixSocket<scion::posix::IPEndpoint>>;

    static void SetUpTestSuite()
    {
        using namespace scion;
        using namespace std::chrono_literals;

        scion_context_opts opts = {};
        opts.daemon_address = nullptr;
        opts.default_isd_asn = unwrap(scion::IsdAsn::Parse("1-ff00:0:1"));
        opts.ports_begin = 31000;
        opts.ports_end = 32767;
        opts.flags = SCION_HOST_CTX_MTU_DISCOVER;
        {
            scion_context* c = nullptr;
            ASSERT_EQ(scion_create_host_context(&c, &opts), SCION_OK);
            ctx.reset(c);
        }
        {
            scion_socket* s = nullptr;
            ASSERT_EQ(scion_socket_create(ctx.get(), &s, SOCK_DGRAM), SCION_OK);
            socket.reset(s);
        }

        ep1 = ep2 = unwrap(Socket::Endpoint::Parse("1-ff00:0:1,::1"));
        sa1 = details::endpoint_cast(ep1);
        ASSERT_FALSE(scion_bind(socket.get(), reinterpret_cast<sockaddr*>(&sa1), sizeof(sa1)));
        scion_getsockname(socket.get(), &sa1);
        ep1 = details::endpoint_cast(&sa1);

        ASSERT_FALSE(socket2.bind(ep2));
        ep2 = socket2.localEp();
        sa2 = details::endpoint_cast(ep2);

        ASSERT_FALSE(scion_connect(socket.get(), &sa2));
        ASSERT_FALSE(socket2.connect(ep1));

        // set to nonblocking so tests fail when packets were not received
        ASSERT_FALSE(scion_set_nonblocking(socket.get(), true));
        ASSERT_FALSE(socket2.setRecvTimeout(1s));
    }

    static void TearDownTestSuite()
    {
        socket2.close();
        socket.reset();
        ctx.reset();
    }

    inline static auto ctx = std::unique_ptr<scion_context, void(*)(scion_context*)>(
        NULL, &scion_delete_host_context);
    inline static auto socket = std::unique_ptr<scion_socket, void(*)(scion_socket*)>(
        NULL, &scion_close);
    inline static Socket socket2;
    inline static scion::ScIPEndpoint ep1, ep2;
    inline static sockaddr_scion sa1, sa2;
};

TEST_F(CInterfaceFixture, PathMTU)
{
    using namespace scion;
    auto path = makePath(
        IsdAsn(Isd(1), Asn(0xff00'0000'0001)),
        IsdAsn(Isd(2), Asn(0xff00'0000'0002)),
        hdr::PathType::SCION,
        Path::Expiry::clock::now(),
        800,
        generic::IPEndpoint::UnspecifiedIPv4(),
        std::span<const std::byte>()
    );
    RawPath rp;
    EXPECT_EQ(scion_discovered_pmtu(
        ctx.get(), reinterpret_cast<scion_path*>(path.get()), &sa1.sscion_addr),
        800
    );
    EXPECT_EQ(scion_discovered_pmtu_raw(
        ctx.get(), reinterpret_cast<scion_raw_path*>(&rp), &sa1.sscion_addr),
        1280
    );
}

TEST_F(CInterfaceFixture, NameResolution)
{
    using namespace scion;
    using namespace scion::details;

    std::array<sockaddr_scion, 2> ep = {};
    size_t len = 1;
    EXPECT_EQ(scion_resolve_name(ctx.get(), "localhost", ep.data(), &len), SCION_BUFFER_TOO_SMALL);
    EXPECT_EQ(len, 2);
    auto expected = endpoint_cast(unwrap(ScIPEndpoint::Parse("1-ff00:0:1,127.0.0.1")));
    EXPECT_TRUE(scion_sockaddr_are_equal(&ep[0], &expected));

    len = ep.size();
    EXPECT_EQ(scion_resolve_name(ctx.get(), "localhost", ep.data(), &len), SCION_OK);
    EXPECT_EQ(len, 2);
    auto expected2 = endpoint_cast(unwrap(ScIPEndpoint::Parse("1-ff00:0:1,::1")));
    EXPECT_TRUE(scion_sockaddr_are_equal(&ep[0], &expected));
    EXPECT_TRUE(scion_sockaddr_are_equal(&ep[1], &expected2));

    len = ep.size();
    EXPECT_EQ(scion_resolve_name(ctx.get(), "netsys.ovgu.de", ep.data(), &len), SCION_OK);
    EXPECT_EQ(len, 1);
    auto expected3 = endpoint_cast(unwrap(ScIPEndpoint::Parse("19-ffaa:1:c3f,127.0.0.1")));
    EXPECT_TRUE(scion_sockaddr_are_equal(&ep[0], &expected3));
}

TEST_F(CInterfaceFixture, NameResolutionAsync)
{
    using namespace scion;
    using namespace scion::details;
    scion_restart(ctx.get());

    struct user_data
    {
        std::array<sockaddr_scion, 2> ep = {};
        size_t len = ep.size();
    } data;

    auto callback = [] (scion_error status, void* user_ptr) {
        auto data = reinterpret_cast<user_data*>(user_ptr);
        ASSERT_EQ(status, SCION_OK);
        ASSERT_EQ(data->len, 1);
        auto expected = endpoint_cast(unwrap(ScIPEndpoint::Parse("19-ffaa:1:c3f,127.0.0.1")));
        ASSERT_TRUE(scion_sockaddr_are_equal(&data->ep[0], &expected));
    };

    scion_resolve_name_async(ctx.get(), "netsys.ovgu.de", data.ep.data(), &data.len,
        scion_async_resolve_handler{callback, &data});
    scion_run(ctx.get());
}

TEST_F(CInterfaceFixture, Measure)
{
    using namespace scion;

    RawPath path;
    scion_packet pkt = {};
    pkt.addr = nullptr;
    SCION_SET_PATH(pkt, reinterpret_cast<scion_raw_path*>(&path));

    size_t size = 0;
    ASSERT_FALSE(scion_measure(socket.get(), &pkt, &size));
    EXPECT_EQ(size, 68);
}

TEST_F(CInterfaceFixture, Send)
{
    using namespace scion;

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto headers = std::unique_ptr<scion_hdr_cache, void(*)(scion_hdr_cache*)>(
        scion_hdr_cache_allocate(), &scion_hdr_cache_free);
    RawPath path;
    sockaddr_in6 underlay = {};
    underlay.sin6_family = AF_INET6;
    std::memcpy(&underlay.sin6_addr, sa2.sscion_addr.u.sscion_addr, 16);
    underlay.sin6_port = sa2.sscion_port;

    size_t n = payload.size();
    scion_packet pkt = {};
    pkt.addr = nullptr;
    pkt.underlay = reinterpret_cast<sockaddr*>(&underlay);
    pkt.underlay_len = sizeof(underlay);
    SCION_SET_PATH(pkt, reinterpret_cast<scion_raw_path*>(&path));
    ASSERT_FALSE(scion_send(socket.get(), headers.get(), payload.data(), &n, &pkt));
    ASSERT_EQ(n, payload.size());

    std::vector<std::byte> buffer(512);
    Socket::Endpoint from;
    auto recvd = socket2.recvFrom(buffer, from);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);

    // send again with cached headers
    SCION_SET_PATH(pkt, NULL);
    ASSERT_FALSE(scion_send_cached(socket.get(), headers.get(), payload.data(), &n, &pkt));
    ASSERT_EQ(n, payload.size());

    recvd = socket2.recvFrom(buffer, from);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
}

TEST_F(CInterfaceFixture, Recv)
{
    using namespace scion;

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    HeaderCache headers;
    RawPath path;
    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep1.localEp()));
    auto sent = socket2.sendTo(headers, ep1, path, nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);

    std::vector<std::byte> buffer(512);
    size_t n = buffer.size();
    sockaddr_in6 ulSource;
    scion_packet pkt = {};
    pkt.underlay = reinterpret_cast<sockaddr*>(&ulSource);
    pkt.underlay_len = sizeof(ulSource);
    scion_error err = SCION_OK;
    auto recvd = reinterpret_cast<std::byte*>(
        scion_recv(socket.get(), buffer.data(), &n, &pkt, &err));
    ASSERT_TRUE(recvd);
    ASSERT_FALSE(err);
    ASSERT_EQ(n, payload.size());
    ASSERT_THAT(std::span<std::byte>(recvd, n), testing::ElementsAreArray(payload));
    ASSERT_EQ(ulSource.sin6_family, AF_INET6);
    ASSERT_EQ(ulSource.sin6_port, sa2.sscion_port);
    ASSERT_TRUE(std::memcmp(&ulSource.sin6_addr, &sa2.sscion_addr.u, 16) == 0);
}

TEST_F(CInterfaceFixture, SCMPHandler)
{
    using namespace scion;

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    HeaderCache headers;
    RawPath path;
    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep1.localEp()));

    struct Handler {
        static void callback(const scion_scmp_message* message, void* user_ptr) {
            reinterpret_cast<Handler*>(user_ptr)->msg = *message;
        };
        scion_scmp_message msg = {};
    } handler;
    scion_set_scmp_handler(ctx.get(), &Handler::callback, &handler);

    try {
        auto msg = hdr::ScmpEchoRequest{0, 1};
        auto sent = socket2.sendScmpTo(headers, ep1, path, nh, msg, payload);
        ASSERT_FALSE(isError(sent)) << getError(sent);
        // send a normal packet so recv returns without error
        sent = socket2.sendTo(headers, ep1, path, nh, payload);
        ASSERT_FALSE(isError(sent)) << getError(sent);

        auto rp = std::unique_ptr<scion_raw_path, void(*)(scion_raw_path*)>(
            scion_raw_path_allocate(), &scion_raw_path_free);
        scion_packet pkt = {};
        SCION_SET_PATH(pkt, rp.get());
        std::vector<std::byte> buffer(512);
        size_t n = buffer.size();
        scion_error err = SCION_OK;
        ASSERT_TRUE(scion_recv(socket.get(), buffer.data(), &n, &pkt, &err));
        ASSERT_FALSE(err);
        ASSERT_EQ(handler.msg.type, SCION_SCMP_ECHO_REQUEST);
        ASSERT_EQ(handler.msg.params.echo.code, 0);
        ASSERT_EQ(handler.msg.params.echo.id, 0);
        ASSERT_EQ(handler.msg.params.echo.seq, 1);
        ASSERT_TRUE(scion_addr_are_equal(&handler.msg.from, &sa2.sscion_addr));
        ASSERT_EQ(handler.msg.path, rp.get());
        ASSERT_EQ(handler.msg.payload_len, payload.size());
        ASSERT_TRUE(std::memcmp(handler.msg.payload, payload.data(), payload.size()) == 0);
        scion_set_scmp_handler(ctx.get(), NULL, NULL);
    } catch (...) {
        scion_set_scmp_handler(ctx.get(), NULL, NULL);
        throw;
    }
}

TEST_F(CInterfaceFixture, AsyncSend)
{
    using namespace scion;
    scion_restart(ctx.get());

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto headers = std::unique_ptr<scion_hdr_cache, void(*)(scion_hdr_cache*)>(
        scion_hdr_cache_allocate(), &scion_hdr_cache_free);
    RawPath path;
    sockaddr_in6 underlay = {};
    underlay.sin6_family = AF_INET6;
    std::memcpy(&underlay.sin6_addr, sa2.sscion_addr.u.sscion_addr, 16);
    underlay.sin6_port = sa2.sscion_port;

    scion_packet pkt = {};
    pkt.addr = &sa2;
    pkt.underlay = reinterpret_cast<sockaddr*>(&underlay);
    pkt.underlay_len = sizeof(underlay);
    SCION_SET_PATH(pkt, reinterpret_cast<scion_raw_path*>(&path));

    auto callback = [] (scion_error status, size_t n, void* user_ptr) {
        ASSERT_EQ(status, SCION_OK);
        ASSERT_EQ(n, payload.size());
    };

    scion_send_async(socket.get(), headers.get(), payload.data(), payload.size(), &pkt,
        scion_async_send_handler{
            .callback = callback,
            .user_ptr = NULL,
    });
    ASSERT_EQ(scion_run_for(ctx.get(), 1000), 1);

    std::vector<std::byte> buffer(512);
    auto recvd = socket2.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));

    // send again with cached headers
    scion_restart(ctx.get());
    scion_send_cached_async(socket.get(), headers.get(), payload.data(), payload.size(), &pkt,
        scion_async_send_handler{
            .callback = callback,
            .user_ptr = NULL,
    });
    ASSERT_EQ(scion_run_for(ctx.get(), 1000), 1);

    recvd = socket2.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(CInterfaceFixture, AsyncRecv)
{
    using namespace scion;
    scion_restart(ctx.get());

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep1.localEp()));
    auto sent = socket2.send(headers, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);

    struct Data
    {
        Data()
            : buffer(1024)
        {}
        std::vector<std::byte> buffer;
        scion_packet pkt = {};
    } d;

    auto callback = [] (scion_error status, void* recvd, size_t n, void* user_ptr) {
        ASSERT_EQ(status, SCION_OK);
        ASSERT_EQ(n, payload.size());
        ASSERT_THAT(
            std::span<std::byte>(reinterpret_cast<std::byte*>(recvd), n),
            testing::ElementsAreArray(payload));
    };

    scion_recv_async(socket.get(), d.buffer.data(), d.buffer.size(), &d.pkt,
        scion_async_recv_handler{
            .callback = callback,
            .user_ptr = &d,
    });
    ASSERT_EQ(scion_run_for(ctx.get(), 1000), 1);
}

TEST_F(CInterfaceFixture, AsyncRecvFromVia)
{
    using namespace scion;
    scion_restart(ctx.get());

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep1.localEp()));
    auto sent = socket2.send(headers, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);

    struct Data
    {
        Data()
            : buffer(1024), path(scion_raw_path_allocate(), &scion_raw_path_free)
        {}
        std::vector<std::byte> buffer;
        sockaddr_scion from;
        sockaddr_in6 ulSource;
        std::unique_ptr<scion_raw_path, void(*)(scion_raw_path*)> path;
        scion_packet pkt = {};
    } d;
    d.pkt.addr = &d.from;
    d.pkt.underlay = reinterpret_cast<sockaddr*>(&d.ulSource);
    d.pkt.underlay_len = sizeof(d.ulSource);
    SCION_SET_PATH(d.pkt, d.path.get());

    auto callback = [] (scion_error status, void* recvd, size_t n, void* user_ptr) {
        auto d = reinterpret_cast<Data*>(user_ptr);
        ASSERT_EQ(status, SCION_OK);
        ASSERT_EQ(n, payload.size());
        ASSERT_THAT(
            std::span<std::byte>(reinterpret_cast<std::byte*>(recvd), n),
            testing::ElementsAreArray(payload));
        EXPECT_TRUE(scion_sockaddr_are_equal(&d->from, &sa2));
        EXPECT_EQ(d->ulSource.sin6_family, AF_INET6);
        EXPECT_EQ(d->ulSource.sin6_port, sa2.sscion_port);
        EXPECT_TRUE(std::memcmp(&d->ulSource.sin6_addr, &sa2.sscion_addr.u, 16) == 0);
    };

    scion_recv_async(socket.get(), d.buffer.data(), d.buffer.size(), &d.pkt,
        scion_async_recv_handler{
            .callback = callback,
            .user_ptr = &d,
    });
    ASSERT_EQ(scion_run_for(ctx.get(), 1000), 1);
}

class CInterfacePathFixture : public testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        auto src = IsdAsn(Isd(1), Asn(0xff00'0000'0111));
        auto dst = IsdAsn(Isd(2), Asn(0xff00'0000'0222));
        auto buf = loadPackets("path/data/path_metadata_3hops.bin").at(0);
        pb.ParseFromArray(buf.data(), (int)(buf.size()));
        auto flags = daemon::PathReqFlags::Interfaces;
        ppath = daemon::details::pathFromProtobuf(src, dst, pb, flags).value();
        path = reinterpret_cast<scion_path*>(ppath.get());
    };

    inline static proto::daemon::v1::Path pb;
    inline static scion::PathPtr ppath;
    inline static scion_path* path;
};

TEST_F(CInterfacePathFixture, Getters)
{
    EXPECT_EQ(scion_path_first_as(path), 0x0001'ff00'0000'0111ull);
    EXPECT_EQ(scion_path_last_as(path), 0x0002'ff00'0000'0222ull);
    EXPECT_EQ(scion_path_type(path), SCION_PATH_SCION);
    EXPECT_EQ(scion_path_expiry(path), 1712950886ull * 1000 * 1000 * 1000);
    EXPECT_EQ(scion_path_mtu(path), 1472);
    EXPECT_EQ(scion_path_hop_count(path), 2);
    EXPECT_FALSE(scion_path_broken(path));
    auto now = scion_time_steady();
    scion_path_set_broken(path, now);
    EXPECT_EQ(scion_path_broken(path), now);
}

TEST_F(CInterfacePathFixture, MetadataHops)
{
    std::vector<scion_hop> hops;
    size_t len = hops.size();
    ASSERT_EQ(scion_path_meta_hops(path, hops.data(), &len), SCION_BUFFER_TOO_SMALL);
    hops.resize(len);
    ASSERT_EQ(scion_path_meta_hops(path, hops.data(), &len), SCION_OK);
    static const std::array<scion_hop, 3> expectedHops = {
        scion_hop{
            .isd_asn = 0x1ff0000000111ull,
            .ingress = 0,
            .egress = 2,
        },
        scion_hop{
            .isd_asn = 0x2ff0000000211ull,
            .ingress = 5,
            .egress = 4,
        },
        scion_hop{
            .isd_asn = 0x2ff0000000222ull,
            .ingress = 3,
            .egress = 0,
        },
    };
    EXPECT_THAT(hops, testing::ElementsAreArray(expectedHops));
}

TEST_F(CInterfacePathFixture, Digest)
{
    scion_digest digest = {};
    scion_path_digest(path, &digest);
    EXPECT_EQ(digest.value[0], 0xe7cc783a3f31d342ull);
    EXPECT_EQ(digest.value[1], 0x32437bfd0d34741aull);
}

TEST_F(CInterfacePathFixture, Print)
{
    size_t len = 0;
    ASSERT_EQ(scion_path_print(path, NULL, &len), SCION_BUFFER_TOO_SMALL);
    char buffer[128];
    len = sizeof(buffer);
    ASSERT_EQ(scion_path_print(path, buffer, &len), SCION_OK);
    EXPECT_STREQ(buffer, "1-ff00:0:111 2>5 2-ff00:0:211 4>3 2-ff00:0:222");
}

TEST_F(CInterfacePathFixture, DataPlanePath)
{
    const uint8_t* encoded = nullptr;
    size_t len = 0;
    scion_path_encoded(path, &encoded, &len);
    ASSERT_EQ(len, pb.raw().size());
    ASSERT_TRUE(std::memcmp(encoded, pb.raw().data(), len) == 0);
}

TEST_F(CInterfacePathFixture, NextHopp)
{
    using namespace scion;
    sockaddr_storage nh;
    socklen_t len = sizeof(nh);
    ASSERT_EQ(scion_path_next_hop(path, reinterpret_cast<sockaddr*>(&nh), &len), SCION_OK);
    ASSERT_EQ(len, sizeof(sockaddr_in6));
    ASSERT_EQ(nh.ss_family, AF_INET6);
    auto inet6 = reinterpret_cast<sockaddr_in6*>(&nh);
    sockaddr_in6 expected = unwrap(toUnderlay<sockaddr_in6>(
        unwrap(generic::IPEndpoint::Parse("[fd00:f00d:cafe::7f00:19]:31024"))));
    ASSERT_EQ(inet6->sin6_family, expected.sin6_family);
    ASSERT_EQ(inet6->sin6_port, expected.sin6_port);
    ASSERT_EQ(inet6->sin6_flowinfo, expected.sin6_flowinfo);
    ASSERT_EQ(inet6->sin6_scope_id, expected.sin6_scope_id);
    ASSERT_TRUE(IN6_ARE_ADDR_EQUAL(&inet6->sin6_addr, &expected.sin6_addr));
}

TEST(CInterface, RawPath)
{
    using namespace scion;
    auto src = IsdAsn(Isd(1), Asn(0xff00'0000'0111));
    auto dst = IsdAsn(Isd(2), Asn(0xff00'0000'0222));
    auto buf = loadPackets("path/data/raw_path.bin").at(0);
    RawPath rpath(src, dst, hdr::PathType::SCION, buf);
    auto rp = reinterpret_cast<scion_raw_path*>(&rpath);

    EXPECT_EQ(scion_raw_path_first_as(rp), src);
    EXPECT_EQ(scion_raw_path_last_as(rp), dst);
    EXPECT_EQ(scion_raw_path_type(rp), SCION_PATH_SCION);
    scion_digest digest = {};
    scion_raw_path_digest(rp, &digest);
    EXPECT_TRUE(SCION_DIGEST_EQUAL(digest, digest));

    const uint8_t* encoded = nullptr;
    size_t len = 0;
    scion_raw_path_encoded(rp, &encoded, &len);
    ASSERT_EQ(len, buf.size());
    ASSERT_TRUE(std::memcmp(encoded, buf.data(), len) == 0);

    ASSERT_FALSE(scion_raw_path_reverse(rp));
    EXPECT_EQ(scion_raw_path_first_as(rp), dst);
    EXPECT_EQ(scion_raw_path_last_as(rp), src);

    scion_digest digestRev = {};
    scion_raw_path_digest(rp, &digestRev);
    EXPECT_FALSE(SCION_DIGEST_EQUAL(digest, digestRev));

    len = 0;
    ASSERT_EQ(scion_raw_path_print(rp, NULL, &len), SCION_BUFFER_TOO_SMALL);
    char buffer[128];
    len = sizeof(buffer);
    ASSERT_EQ(scion_raw_path_print(rp, buffer, &len), SCION_OK);
    EXPECT_STREQ(buffer, "2-ff00:0:222 12>11 10>9 8>7 6>5 1>2 3>4 1-ff00:0:111");
}
