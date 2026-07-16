// Copyright (c) 2026 Lars-Christian Schulz
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

#include "config.hpp"

#include <scion/scion_asio.hpp>

#include <chrono>
#include <cstdlib>
#include <format>
#include <optional>

using namespace scion;


static int reportDaemonError(const std::string& addr, std::error_code ec)
{
    std::cerr << std::format("Communication with sciond at {} failed: {}\n", addr, fmtError(ec));
    return EXIT_FAILURE;
}

class IdIntCommunicator
{
protected:
    using Socket = asio::UdpSocket;
    using Endpoint = Socket::UnderlayEp;

    Config m_cfg;
    boost::asio::io_context m_ioCtx;
    Socket m_socket;
    daemon::GrpcDaemonClient m_sciond;
    drkey::KeyCache m_keyCache;
    bool m_shouldExit = false;

    int initialize()
    {
        auto info = m_sciond.rpcAsInfo(IsdAsn());
        if (isError(info)) {
            return reportDaemonError(m_cfg.sciond, info.error());
        }
        auto ports = m_sciond.rpcPortRange();
        if (isError(ports)) {
            return reportDaemonError(m_cfg.sciond, ports.error());
        }
        const auto bindAddr = ScIPEndpoint(info->isdAsn, m_cfg.local);
        if (auto ec = m_socket.bind(bindAddr, ports->first, ports->second); ec) {
            std::cerr << std::format("Can't bind to {} : {}\n", bindAddr, fmtError(ec));
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    void stop()
    {
        m_shouldExit = true;
        m_socket.cancel();
    }

    Maybe<drkey::Key> fetchASHostKey(
        const ScIPAddress& srcHost,
        const ScIPAddress& dstHost,
        DRKeyProtocol proto,
        drkey::TimePoint validAt)
    {
        daemon::DRKeyASHostRequest req = {
            .valTime = validAt,
            .protocol = proto,
            .srcIA = srcHost.isdAsn(),
            .dstIA = dstHost.isdAsn(),
            .dstHost = std::format("{}", dstHost.host()),
        };
        return m_sciond.rpcDRKeyASHost(req);
    }

    Maybe<drkey::Key> fetchHostHostKey(
        const ScIPAddress& srcHost,
        const ScIPAddress& dstHost,
        DRKeyProtocol proto,
        drkey::TimePoint validAt)
    {
        daemon::DRKeyHostHostRequest req = {
            .valTime = validAt,
            .protocol = proto,
            .srcIA = srcHost.isdAsn(),
            .dstIA = dstHost.isdAsn(),
            .srcHost = std::format("{}", srcHost.host()),
            .dstHost = std::format("{}", dstHost.host()),
        };
        return m_sciond.rpcDRKeyHostHost(req);
    }

    IdIntCommunicator(const Config& cfg)
        : m_cfg(cfg)
        , m_ioCtx(1)
        , m_socket(m_ioCtx)
        , m_sciond(cfg.sciond)
        , m_keyCache(DRKeyProtocol::IDINT)
    {}
};


class Server : public IdIntCommunicator
{
protected:
    HeaderCache<> m_headers;
    RawPath m_path;
    idint::IdInt<> m_telemetry;
    std::vector<std::byte> m_recvBuf;
    std::vector<std::byte> m_sendBuf;

public:
    Server(const Config& cfg)
        : IdIntCommunicator(cfg)
        , m_recvBuf(9000)
        , m_sendBuf(9000)
    {}

    int run()
    {
        if (int res = initialize(); res) {
            return res;
        }
        return EXIT_SUCCESS;
    };

private:
    boost::asio::awaitable<std::error_code> serverLoop()
    {
        ScIPEndpoint from;
        Endpoint ulSource;
        idint::IntRequest req;
        idint::IdInt telemetry;
        std::array<ext::Extension*, 1> hbh = {&telemetry};
        constexpr auto token = boost::asio::use_awaitable;

        while (!m_shouldExit) {
            auto recvd = co_await m_socket.recvFromViaExtAsync(
                m_recvBuf, from, m_path, ulSource, hbh, ext::NoExtensions, token);
            if (recvd.has_value() && telemetry.isValid()) {
                std::span<std::byte> payload;
                if (auto ec = prepareResponse(from, req, payload); ec) {
                    auto sent = co_await m_socket.sendToExtAsync(
                        m_headers, from, m_path, ulSource, hbh, payload, token);
                } else {
                }
            }
        }
    };

    std::error_code prepareResponse(
        const ScIPEndpoint& remote,
        idint::IntRequest& req,
        std::span<std::byte>& payload)
    {
        using namespace std::chrono;

        if (auto ec = m_path.reverseInPlace(); ec) {
            return ec;
        }

        // Put ID-INT header in payload of the response
        WriteStream ws(m_sendBuf);
        auto err = NullStreamError;
        if (!ws.advanceBytes(2, err) || !m_telemetry.serialize(ws, 2, err)) {
            return ErrorCode::LogicError;
        }

        // Get key for authenticating out response
        auto validAt = std::chrono::utc_clock::now();
        auto key = m_keyCache.getHostHostKey(m_socket.localEp().address(), remote.address(), validAt,
            [this](auto&&... args) {
                return fetchHostHostKey(args...);
            }
        );
        if (isError(key)) return key.error();

        // Copy the original metadata request
        if (auto ec = m_telemetry.recoverRequest(req); ec) {
            return ec;
        }
        req.vtype = idint::Verifier::Destination;
        req.identifier.timestamp = duration_cast<nanoseconds>(
            validAt.time_since_epoch()).count() & ~(~0ull << 48);
        setServerMetadata(req);

        if (!ws.lookback(payload, WriteStream::npos, err)) {
            return ErrorCode::LogicError;
        }
        return ErrorCode::Ok;
    }

    void setServerMetadata(idint::IntRequest& req)
    {
        using namespace idint;
        for (std::size_t i = 0; i < req.instructions.size(); ++i) {
            auto instr = req.instructions[i];
            switch (instr) {
            case Instr::Isd:
                req.srcData.setMetadata(i, instr, (std::uint16_t)m_socket.localEp().isdAsn().isd());
                break;
            case Instr::Asn:
                req.srcData.setMetadata(i, instr, (std::uint64_t)m_socket.localEp().isdAsn().asn());
                break;
            case Instr::NodeIpv4Addr:
                if (auto ip = m_socket.localEp().host(); ip.is4()) {
                    req.srcData.setMetadata(i, instr, ip.getIPv4());
                }
                break;
            case Instr::NodeIpv6AddrH:
                if (auto ip = m_socket.localEp().host(); ip.is6()) {
                    req.srcData.setMetadata(i, instr, ip.getIPv6().first);
                }
                break;
            case Instr::NodeIpv6AddrL:
                if (auto ip = m_socket.localEp().host(); ip.is6()) {
                    req.srcData.setMetadata(i, instr, ip.getIPv6().second);
                }
                break;
            case Instr::Uptime:
                break;
            case Instr::IngressTstamp:
                break;
            default:
                break; // not response
            }
        }
    }
};

class Client : public IdIntCommunicator
{
protected:
    PathCache m_pathCache;

public:
    Client(const Config& cfg)
        : IdIntCommunicator(cfg)
    {}

    int run()
    {
        if (int res = initialize(); res) {
            return res;
        }
        m_socket.setNextScmpHandler(&m_pathCache);

        auto queryPaths = [this](PathCache& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
            using namespace daemon;
            auto flags = PathReqFlags::Refresh | PathReqFlags::AllMetadata;
            std::vector<PathPtr> paths;
            if (auto ec = m_sciond.rpcPaths(src, dst, flags, std::back_inserter(paths)); ec) {
                return ec;
            }
            cache.store(src, dst, paths);
            return ErrorCode::Ok;
        };
        auto paths = m_pathCache.lookup(
            m_socket.localEp().isdAsn(), m_cfg.client.remote.isdAsn(), queryPaths, true);

        auto path = paths->at(0); // TODO
        auto nh = generic::toUnderlay<Endpoint>(path->nextHop()).value();

        if (m_cfg.client.stun) { // TODO
            m_socket.requestStunMapping(nh);
            m_socket.recvStunResponse();
        }

        return EXIT_SUCCESS;
    };
};
