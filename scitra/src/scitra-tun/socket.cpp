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

#include "scitra/scitra-tun/socket.hpp"
#include "scion/asio/addresses.hpp"

#include <spdlog/spdlog.h>

#include <random>


static bool ENABLE_STUN = false;
static std::uint16_t STUN_PORT = 3478;
static auto NAT_TIMEOUT = std::chrono::seconds(30);

void Socket::configureStun(bool enable, std::uint16_t port, std::uint32_t timeoutSec)
{
    ENABLE_STUN = enable;
    STUN_PORT = port;
    NAT_TIMEOUT = std::chrono::seconds(timeoutSec);
}

std::error_code Socket::open(const asio::ip::address& bindAddress)
{
    boost::system::error_code ec;
    int res = 0;

    auto proto = bindAddress.is_v6() ? asio::ip::udp::v6() : asio::ip::udp::v4();
    m_underlay.open(proto, ec);
    if (ec) return ec;

    const auto sockfd = m_underlay.native_handle();

    m_underlay.bind(asio::ip::udp::endpoint(bindAddress, m_localPort), ec);
    if (ec) return ec;
    m_localAddress = generic::toGenericAddr(bindAddress);

    // Disable automatic fragmentation of large UDP packets.
    int mtuDisc = IP_PMTUDISC_DO;
    if (proto.family() == AF_INET) {
        res = setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &mtuDisc, sizeof(mtuDisc));
    } else {
        res = setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &mtuDisc, sizeof(mtuDisc));
    }
    if (res) return std::error_code(errno, std::system_category());

#if 0
    // Enable extended error queue.
    const int recvErr = 1;
    if (proto.family() == AF_INET) {
        res = setsockopt(sockfd, IPPROTO_IP, IP_RECVERR, &recvErr, sizeof(recvErr));
    } else  {
        res = setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVERR, &recvErr, sizeof(recvErr));
    }
    if (res) return std::error_code(errno, std::system_category());
#endif
    return ScitraError::Ok;
}

asio::awaitable<std::error_code>
Socket::recvPacket(PacketBuffer& pkt, asio::ip::udp::endpoint& from)
{
    // 4 bytes headroom for the following edge case: A SCION header with an empty path and IPv4
    // host addresses is 4 bytes smaller than the IPv6 header created by the translator.
    constexpr std::size_t IP_HEADROOM = 4;
    auto buffer = pkt.clearAndGetBuffer(IP_HEADROOM);

    constexpr auto token = boost::asio::as_tuple(boost::asio::use_awaitable);
    auto [ec, n] = co_await m_underlay.async_receive_from(asio::buffer(buffer), from, token);
    if (ec) co_return ec;
    DBG_TIME_BEGIN(lastRx);
    ec = pkt.parsePacket(n, true);
    if (ec) co_return ec;

    if (ENABLE_STUN) {
        if (pkt.stunValid) {
            if (pkt.stun.type == hdr::StunMsgType::BindingRequest) {
                // Persistent sockets answer STUN binding request
                if (!m_persistent) co_return ScitraError::InvalidPacket;
                spdlog::debug("Socket {}: Responding to STUN binding request from {}",
                    m_localPort, from);
                if (ec = respondToBindingReq(pkt, from); ec) {
                    spdlog::debug("Socket {}: Error sending STUN response to {}: {}",
                        from, fmtError(ec));
                }
                co_return ScitraError::StunReceived;
            } else if (pkt.stun.type == hdr::StunMsgType::BindingResponse) {
                std::lock_guard stunLock(m_stun.mutex);
                if (from.address() != m_stun.expectedStunServer)
                    co_return ScitraError::InvalidPacket;
                if (pkt.stun.type != hdr::StunMsgType::BindingResponse)
                    co_return ScitraError::InvalidPacket;
                if (pkt.stun.transaction != m_stun.stunTx)
                    co_return ScitraError::InvalidPacket;
                m_stun.expectStunResponse = 0;
                if (pkt.stun.mapped) {
                    spdlog::debug("Socket {}: STUN binding response from {}: {} -> {}",
                        m_localPort, from,
                        generic::IPEndpoint(m_localAddress, m_localPort),
                        pkt.stun.mapped->address);
                    m_mapped.store(std::make_shared<generic::IPEndpoint>(pkt.stun.mapped->address));
                    if (m_stun.heldPacket) {
                        if (auto ec = sendHeldPacket(); ec) {
                            spdlog::debug("Socket {}: Error sending held packet to {}: {}",
                                m_localPort, m_stun.heldPacket->second, fmtError(ec));
                        }
                        m_stun.heldPacket = nullptr;
                        m_lastUsed.store(std::chrono::steady_clock::now());
                    }
                }
                co_return ScitraError::StunReceived;
            }
            co_return ScitraError::InvalidPacket;
        }
        ingressNat(pkt, from);
    }
    co_return ScitraError::Ok;
}

std::error_code Socket::sendPacket(PacketBuffer& pkt, const asio::ip::udp::endpoint& nextHop,
    const std::chrono::steady_clock::time_point& t)
{
    if (ENABLE_STUN) {
        if (t - m_lastUsed.load() > NAT_TIMEOUT) {
            if (auto ec = requestStunMapping(pkt, nextHop); ec != ScitraError::StunReceived)
                return ec;
        }
        egressNat(pkt);
    }

    auto buffer = pkt.emitPacket(true);
    if (!buffer.has_value()) {
        return buffer.error();
    }
    boost::system::error_code ec;
    auto n = m_underlay.send_to(asio::buffer(*buffer), nextHop, 0, ec);
    if (ec) {
        if (ec == std::errc::message_size) {
            spdlog::warn("Socket {}: Message size error sending to {} ({} bytes)",
                m_localPort, nextHop, buffer->size());
        }
        return ec;
    }
    if (n < buffer->size()) return ScitraError::PartialWrite;
    m_lastUsed.store(t);
    return ScitraError::Ok;
}

// Respond to STUN binding request.
std::error_code Socket::respondToBindingReq(
    const PacketBuffer& pkt, const asio::ip::udp::endpoint& from)
{
    // Prepare binding response with the observed remote endpoint
    hdr::STUN stun;
    stun.type = hdr::StunMsgType::BindingResponse;
    stun.transaction = pkt.stun.transaction;
    stun.mapped = hdr::StunXorMappedAddress{generic::toGenericEp(from)};

    // Serialize response
    std::array<std::byte, 44> buffer;
    WriteStream ws(std::span<std::byte>(buffer.data(), buffer.size()));
    if (!stun.serialize(ws, NullStreamError)) {
        return ScitraError::LogicError;
    }
    const std::size_t size = ws.getPtr() - buffer.data();

    // Send response packet
    boost::system::error_code ec;
    auto n = m_underlay.send_to(asio::buffer(buffer, size), from, 0, ec);
    if (ec) return ec;
    if (n < size) return ScitraError::PartialWrite;
    return ScitraError::Ok;
}

// Send a STUN binding request to `nextHop`.
// Returns ScitraError::StunReceived if no more STUN requests should be sent.
std::error_code Socket::requestStunMapping(const PacketBuffer& pkt, asio::ip::udp::endpoint nextHop)
{
    hdr::STUN stun;
    stun.type = hdr::StunMsgType::BindingRequest;

    // Pick a new random transaction ID
    std::random_device rd;
    std::uniform_int_distribution<std::uint64_t> dist;
    auto rand = dist(rd);
    std::memcpy(stun.transaction.data(), &rand, 8);
    rand = dist(rd);
    std::memcpy(stun.transaction.data() + 8, &rand, 4);

    // Prepare STUN binding request
    std::array<std::byte, 20> buffer;
    WriteStream ws(std::span<std::byte>(buffer.data(), buffer.size()));
    if (!stun.serialize(ws, NullStreamError)) {
        return ScitraError::LogicError;
    }

    // Send request packet
    std::lock_guard stunLock(m_stun.mutex);
    if (m_stun.expectStunResponse >= 3) {
        // Give up on STUN and try direct connection
        spdlog::debug("Socket {}: STUN timeout", m_localPort);
        m_stun.expectStunResponse = 0;
        m_mapped.store(std::make_shared<generic::IPEndpoint>(m_localAddress, m_localPort));
        return ScitraError::StunReceived;
    }

    auto server = nextHop;
    if (STUN_PORT) server.port(STUN_PORT);
    boost::system::error_code ec;
    auto n = m_underlay.send_to(asio::buffer(buffer), server, 0, ec);
    if (ec) return ec;
    if (n < buffer.size()) return ScitraError::PartialWrite;
    spdlog::debug("Socket {}: Sent STUN binding request to {}", m_localPort, server);

    // Record information about expected response
    m_stun.expectStunResponse++;
    m_stun.expectedStunServer = server.address();
    m_stun.stunTx = stun.transaction;
    m_stun.heldPacket = std::make_unique<StunState::HeldPacket>(pkt, nextHop);
    return ScitraError::Ok;
}

// Send the packet buffered at the last STUN binding request.
// Precondition: m_stun.mutex is locked.
std::error_code Socket::sendHeldPacket()
{
    assert(m_stun.heldPacket);
    auto& [pkt, nh] = *m_stun.heldPacket;
    egressNat(pkt);
    auto buffer = pkt.emitPacket(true);
    if (isError(buffer)) return buffer.error();
    boost::system::error_code ec;
    auto n = m_underlay.send_to(asio::buffer(*buffer), nh, 0, ec);
    if (n < buffer->size()) return ScitraError::PartialWrite;
    if (ec) return ec;
    return ScitraError::Ok;
}

void Socket::ingressNat(PacketBuffer& pkt, const asio::ip::udp::endpoint& from)
{
    if (auto mapped = m_mapped.load(); mapped) {
        std::uint32_t add = 0, sub = 0;
        if (pkt.scionValid) {
            sub += pkt.sci.dst.checksum();
            pkt.sci.dst = ScIPAddress(pkt.sci.dst.isdAsn(), m_localAddress);
            add += pkt.sci.dst.checksum();
        }
        if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
            sub += pkt.tcp.dport;
            pkt.tcp.dport = m_localPort;
            add += pkt.tcp.dport;
        } else if (pkt.l4Valid == PacketBuffer::L4Type::UDP) {
            sub += pkt.udp.dport;
            pkt.udp.dport = m_localPort;
            add += pkt.udp.dport;
        } else if (pkt.l4Valid == PacketBuffer::L4Type::SCMP) {
            if (pkt.scmp.getType() == hdr::ScmpType::EchoReply) {
                auto& echoReply = std::get<hdr::ScmpEchoReply>(pkt.scmp.msg);
                sub += echoReply.id;
                echoReply.id = m_localPort;
                add += echoReply.id;
            }
        }
        pkt.l4UpdateChecksum(add, sub);
    }
}

void Socket::egressNat(PacketBuffer& pkt)
{
    if (auto mapped = m_mapped.load(); mapped) {
        std::uint32_t add = 0, sub = 0;
        if (pkt.scionValid) {
            sub += pkt.sci.src.checksum();
            pkt.sci.src = ScIPAddress(pkt.sci.src.isdAsn(), mapped->host());
            add += pkt.sci.src.checksum();
        }
        if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
            sub += pkt.tcp.sport;
            pkt.tcp.sport = mapped->port();
            add += pkt.tcp.sport;
        } else if (pkt.l4Valid == PacketBuffer::L4Type::UDP) {
            sub += pkt.udp.sport;
            pkt.udp.sport = mapped->port();
            add += pkt.udp.sport;
        } else if (pkt.l4Valid == PacketBuffer::L4Type::SCMP) {
            if (pkt.scmp.getType() == hdr::ScmpType::EchoRequest) {
                auto& echoReq = std::get<hdr::ScmpEchoRequest>(pkt.scmp.msg);
                sub += echoReq.id;
                echoReq.id = mapped->port();
                add += echoReq.id;
            }
        }
        pkt.l4UpdateChecksum(add, sub);
    }
}
