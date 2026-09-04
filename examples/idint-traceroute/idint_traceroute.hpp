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
#include "tables.hpp"

#include "coroutine_stun.hpp"
#include "path_prompt.hpp"

#include <scion/scion_asio.hpp>
#include <scion/extensions/idint_path_helper.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <functional>
#include <optional>
#include <sstream>

using namespace scion;


/////////////////////////////
// Static Helper Functions //
/////////////////////////////

extern const unsigned int VERSION_MAJOR;
extern const unsigned int VERSION_MINOR;
extern const unsigned int VERSION_PATCH;

template <std::size_t N>
struct std::formatter<std::array<std::byte, N>>
{
    constexpr auto parse(auto& ctx) { return ctx.begin(); }

    auto format(const std::array<std::byte, N>& ary, auto& ctx) const
    {
        auto out = std::format_to(ctx.out(), "{{ ");;
        for (auto b : ary)
            out = std::format_to(out, "{:02x} ", (unsigned)b);
        return std::format_to(out, "}}");
    }
};

static int reportDaemonError(const std::string& addr, std::error_code ec)
{
    std::cerr << std::format("Communication with sciond at {} failed: {}\n", addr, fmtError(ec));
    return EXIT_FAILURE;
}

static void printVerificationError(
    const idint::VerificationStatus& status, const Maybe<drkey::Key>& key)
{
    std::cerr << std::format("Verification error at hop {} ({})",
        status.location.hopIndex, status.location.isdAsn);
    std::cerr << std::format("{}\n", status.location.isSource ? " (source)" : "");
    std::cerr << std::format("expectedMAC = {}, actualMAC = {}\n",
        status.expectedMAC, status.actualMAC);
    if (key.has_value()) std::cerr << std::format("key = {}\n", key->key);
}

static std::string decodeDeviceTypeRole(std::uint64_t value)
{
    std::string role, type;
    switch ((value >> 8) & 0xff) {
    case 1:
        role = "Host";
        break;
    case 2:
        role = "BR";
        break;
    case 3:
        role = "IP Router";
        break;
    case 4:
        role = "Router";
        break;
    case 5:
        role = "SIG";
        break;
    case 6:
        role = "SCITRA";
        break;
    default:
        role = "Other";
        break;
    }
    switch (value & 0xff) {
    case 1:
        type = "scionproto";
        break;
    case 2:
        type = "scion-cpp";
        break;
    default:
        type = "other";
        break;
    }
    return std::format("{} ({})", role, type);
}

static std::string decodeSoftwareVersion(std::uint64_t value)
{
    auto major = (value >> 22) & 0x3ff;
    auto minor = (value >> 12) & 0x3ff;
    auto patch = value & 0xfff;
    return std::format("{}.{}.{}", major, minor, patch);
}

static std::uint32_t encodeSoftwareVersion()
{
    return (std::uint32_t)(
        (std::min(VERSION_MAJOR, 0x3ffu) << 22)
        | (std::min(VERSION_MINOR, 0x3ffu) << 12)
        | std::min(VERSION_PATCH, 0xfffu));
}

static std::string fmtMetadata(std::uint64_t value, idint::Instr instr)
{
    using std::uint32_t;
    using idint::Instr;
    if (instr >= Instr::CpuUserNow && instr <= Instr::HostCpuSoftIrqNow) {
        return std::format("{:8.2f} %", (100.0/65535)*double(value));
    }
    switch (instr) {
    case Instr::DeviceTypeRole:
        return decodeDeviceTypeRole(value);
    case Instr::SoftwareVersion:
        return decodeSoftwareVersion(value);
    case Instr::NodeIpv4Addr:
        return std::format("{}", generic::IPAddress::MakeIPv4((uint32_t)value));
    case Instr::IngressPortSpeed:
    case Instr::EgressPortSpeed:
        return std::format("{} Mbit/s", value);
    case Instr::Uptime:
        return std::format("{} s", value);
    case Instr::RttNextBr:
    case Instr::RttPrevBr:
        return std::format("{:8.3f} ms", 1e-3*double(value));
    case Instr::IngressLinkRx:
    case Instr::IngressLinkTx:
    case Instr::EgressLinkRx:
    case Instr::EgressLinkTx:
        return std::format("{:8.2f} %", (100.0/double(~(~0ull<<32)))*double(value));
    case Instr::IngressTstamp:
    case Instr::EgressTstamp:
        return std::format("{:x}", value);
    case Instr::Asn:
        return std::format("{}", Asn(value));
    case Instr::NodeIpv6AddrH:
    case Instr::NodeIpv6AddrL:
        return std::format("{:016x}", value);
    default:
        return std::format("{}", value);
    }
}

class ScmpPrinter : public ScmpHandlerImpl
{
public:
    virtual bool handleScmpCallback(
        const ScIPAddress& from,
        const RawPath& path,
        const hdr::ScmpMessage& msg,
        std::span<const std::byte> payload) override
    {
        std::cerr << std::format("SCMP from {} : {}\n", from, msg);
        return true;
    }
};

///////////////////////
// IdIntCommunicator //
///////////////////////

// Base class for server and client.
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
    ScmpPrinter m_scmpPrinter;
    idint::Nonce m_nonce;
    bool m_shouldExit = false;

    IdIntCommunicator(IdIntCommunicator&&) = delete;

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
        , m_nonce(idint::randomNonce())
    {}
};

////////////
// Server //
////////////

class Server : public IdIntCommunicator
{
protected:
    HeaderCache<> m_headers;
    RawPath m_path;
    std::vector<std::byte> m_recvBuf;
    std::vector<std::byte> m_responsePayload;

public:
    Server(const Config& cfg)
        : IdIntCommunicator(cfg)
        , m_recvBuf(9000)
        , m_responsePayload(9000)
    {}

    int run()
    {
        if (int res = initialize(); res) {
            return res;
        }
        std::cout << "Server listening at " << m_socket.localEp() << '\n';

        m_socket.setNextScmpHandler(&m_scmpPrinter);

        auto future = boost::asio::co_spawn(m_ioCtx, serverLoop(), boost::asio::use_future);
        m_ioCtx.run();
        if (auto ec = future.get(); ec) {
            std::cerr << "Error: " << fmtError(ec) << '\n';
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    };

private:
    boost::asio::awaitable<std::error_code> serverLoop()
    {
        ScIPEndpoint from;
        Endpoint ulSource;
        idint::IdInt telemetry;
        std::array<ext::Extension*, 1> hbh = {&telemetry};
        std::span<std::byte> payload;
        constexpr auto token = boost::asio::use_awaitable;

        while (!m_shouldExit) {
            auto recvd = co_await m_socket.recvFromViaExtAsync(
                m_recvBuf, from, m_path, ulSource, hbh, ext::NoExtensions, token);
            if (recvd.has_value() && telemetry.isValid()) {
                std::error_code ec;
                if (respond(from, payload, telemetry); !ec) {
                    auto sent = co_await m_socket.sendToExtAsync(
                        m_headers, from, m_path, ulSource, hbh, payload, token);
                    if (!isError(sent)) continue;
                    ec = sent.error();
                }
                std::cerr << std::format(
                    "Error trying to respond to {}: {}\n", from, fmtError(ec));
            }
        }
    };

    std::error_code respond(
        const ScIPEndpoint& remote,
        std::span<std::byte>& payload,
        idint::IdInt<>& telemetry)
    {
        using namespace std::chrono;
        using namespace scion::idint;

        if (auto ec = m_path.reverseInPlace(); ec) {
            return ec;
        }

        // Put ID-INT header in payload of the response without actually
        // serializing the telemetry stack padding to save space. The extension
        // header length is adjusted to reflect the missing padding, but the
        // stack length in the ID-INT header is not as doing so would invalidate
        // the MACs. Parsing this payload requires a parser that is lenient
        // enough to accept the missing padding.
        WriteStream ws(m_responsePayload);
        constexpr auto hbhHdrSize = 2;
        auto err = NullStreamError;
        idint::IdInt<>::WriteOpts opts{hbhHdrSize, true};
        if (!ws.advanceBytes(hbhHdrSize, err) || !telemetry.serialize(ws, opts, err)) {
            return ErrorCode::LogicError;
        }
        if (!ws.lookback(payload, WriteStream::npos, err)) {
            return ErrorCode::LogicError;
        }
        const auto totalExtSize = ws.getPos().first;
        payload[1] = std::byte{(std::uint8_t)(totalExtSize / 4 - 1)};

        // Get key for authenticating end host ID-INT response
        auto validAt = std::chrono::system_clock::now();
        auto key = m_keyCache.getHostHostKey(
            m_socket.localEp().address(), remote.address(), validAt,
            [this](auto&&... args) {
                return fetchHostHostKey(args...);
            }
        );
        if (isError(key)) return key.error();

        // Copy the original metadata request
        IntRequest req;
        if (auto ec = telemetry.recoverRequest(req); ec) {
            return ec;
        }
        req.vtype = Verifier::Destination;
        req.identifier.timestamp = duration_cast<nanoseconds>(
            validAt.time_since_epoch()).count() & ~(~0ull << 48);
        setServerMetadata(req);

        incrementNonce(m_nonce);
        if (auto ec = telemetry.encodeIntRequest(req, *key, &m_nonce); ec) {
            return ec;
        }
        return ErrorCode::Ok;
    }

    void setServerMetadata(idint::IntRequest& req)
    {
        using namespace std::chrono;
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
            case Instr::DeviceTypeRole:
                req.srcData.setMetadata(i, instr, 0x0102);
                break;
            case Instr::SoftwareVersion:
                req.srcData.setMetadata(i, instr, encodeSoftwareVersion());
                break;
            case Instr::IngressTstamp:
                req.srcData.setMetadata(i, instr,
                    duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count());
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
            default:
                break; // not response
            }
        }
    }
};

////////////
// Client //
////////////

class Client : public IdIntCommunicator
{
protected:
    PathCache m_pathCache;
    HeaderCache<> m_headers;
    drkey::Key m_sourceKey;
    std::vector<std::byte> m_recvBuf;

public:
    Client(const Config& cfg)
        : IdIntCommunicator(cfg)
        , m_recvBuf(9000)
    {}

    int run()
    {
        using namespace std::chrono_literals;
        using boost::asio::co_spawn;
        using boost::asio::use_future;

        if (int res = initialize(); res) {
            return res;
        }

        m_socket.setNextScmpHandler(&m_scmpPrinter)->setNextScmpHandler(&m_pathCache);
        m_socket.connect(m_cfg.client.remote);

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
        if (isError(paths) || paths->empty()) {
            std::cerr << "No path to " << m_cfg.client.remote.isdAsn() << '\n';
            return EXIT_FAILURE;
        }

        PathPtr path;
        if (m_cfg.client.interactive) {
            path = paths->at(promptForPath(*paths));
        } else if (m_cfg.client.path >= 0) {
            if ((std::size_t)m_cfg.client.path >= paths->size()) {
                std::cerr << "No path with index " << m_cfg.client.path << '\n';
                return EXIT_FAILURE;
            }
            path = paths->at(m_cfg.client.path);
        } else {
            path = paths->at(0);
        }

        if (m_cfg.client.stun) {
            auto nextHop = path->nextHop(m_cfg.client.remote.localEp());
            auto stunServer = toUnderlay<Socket::UnderlayEp>(
                generic::IPEndpoint(nextHop.host(), 3478)).value();
            auto future = co_spawn(m_ioCtx,
                getStunMapping(m_socket, stunServer, 100ms), use_future);
            m_ioCtx.run();
            if (auto mapped = future.get(); mapped.has_value()) {
                std::cerr << "SNAT mapped address: " << mapped->localEp() << '\n';
            } else {
                std::cerr << "Can't get SNAT address mapping: " << fmtError(mapped.error()) << '\n';
                return EXIT_FAILURE;
            }
        }

        auto future = boost::asio::co_spawn(m_ioCtx, clientLoop(*path), use_future);
        m_ioCtx.run();
        if (auto ec = future.get(); ec) {
            std::cerr << "Error: " << fmtError(ec) << '\n';
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

private:
    Maybe<drkey::Key> fetchHostHostKey(const ScIPAddress& src, const ScIPAddress& dst,
        DRKeyProtocol proto, drkey::KeyCache::TimePoint validAt)
    {
        daemon::DRKeyHostHostRequest req = {
            .valTime = validAt,
            .protocol = proto,
            .srcIA = src.isdAsn(),
            .dstIA = dst.isdAsn(),
            .srcHost = std::format("{}", src.host()),
            .dstHost = std::format("{}", dst.host()),
        };
        return m_sciond.rpcDRKeyHostHost(req);
    }

    Maybe<drkey::Key> fetchASHostKey(const IsdAsn& src, const ScIPAddress& dst,
        DRKeyProtocol proto, drkey::KeyCache::TimePoint validAt)
    {
        daemon::DRKeyASHostRequest req = {
            .valTime = validAt,
            .protocol = proto,
            .srcIA = src,
            .dstIA = dst.isdAsn(),
            .dstHost = std::format("{}", dst.host()),
        };
        return m_sciond.rpcDRKeyASHost(req);
    }

    boost::asio::awaitable<std::error_code> clientLoop(const Path& path)
    {
        using namespace boost::asio;
        steady_timer timer(co_await this_coro::executor);
        while (true) {
            if (auto err = co_await sendProbe(path); err) {
                co_return err;
            }
            if (auto err = co_await receiveResponse(path); err) {
                if (err == ErrorCondition::Timeout)
                    std::cout << "timeout" << std::endl;
                else
                    co_return err;
            }
            if (!m_cfg.client.loop) break;
            timer.expires_after(m_cfg.client.wait);
            co_await timer.async_wait(use_awaitable);
        }
        co_return ErrorCode::Ok;
    }

    boost::asio::awaitable<std::error_code> sendProbe(const Path& via)
    {
        // Get a key for communication with our future self.
        const auto validAt = std::chrono::system_clock::now();
        const auto self = m_socket.localEp().address();
        auto selfKey = m_keyCache.getHostHostKey(self, self, validAt, [this](auto ...args) {
            return this->fetchHostHostKey(args...);
        });
        if (isError(selfKey)) {
            co_return selfKey.error();
        }
        m_sourceKey = *selfKey;

        // Build telemetry request
        idint::IntRequest req;
        req.flags.encrypt = m_cfg.client.encrypt;
        req.skipHops = m_cfg.client.skip;
        req.bitmap[idint::InstrFlag::NodeID] = m_cfg.client.reqNodeId;
        req.bitmap[idint::InstrFlag::NodeCnt] = m_cfg.client.reqNodeCnt;
        req.bitmap[idint::InstrFlag::IgPort] = m_cfg.client.reqIgr;
        req.bitmap[idint::InstrFlag::EgPort] = m_cfg.client.reqEgr;
        req.agrMode = m_cfg.client.agrMode;
        req.stackBytes = m_cfg.client.limit & ~0x03; // must be a multiple of 4
        std::ranges::copy(m_cfg.client.agrFuncs, req.agrFuncs.begin());
        std::ranges::copy(m_cfg.client.instrs, req.instructions.begin());
        req.vtype = idint::Verifier::Source;
        req.identifier.timestamp = validAt.time_since_epoch().count() & ~(~0ll<<48);

        idint::IdInt telemetry;
        auto nonce = idint::randomNonce();
        if (auto err = telemetry.encodeIntRequest(req, m_sourceKey, &nonce); err) {
            co_return err;
        }

        // Send one packet
        auto nextHop = via.nextHop(m_cfg.client.remote.localEp());
        auto underlayDst = toUnderlay<Socket::UnderlayEp>(nextHop).value();
        std::array<ext::Extension*, 1> ext = {&telemetry};
        std::span<std::byte, 0> payload;
        constexpr auto token = boost::asio::use_awaitable;
        auto res = co_await m_socket.sendExtAsync(m_headers, via, underlayDst, ext, payload, token);
        if (isError(res)) co_return res.error();
        co_return ErrorCode::Ok;
    }

    boost::asio::awaitable<std::error_code> receiveResponse(const Path& via)
    {
        using namespace boost::asio::experimental::awaitable_operators;
        using boost::asio::redirect_error;
        using boost::asio::steady_timer;
        constexpr auto token = boost::asio::use_awaitable;

        steady_timer timer(co_await boost::asio::this_coro::executor, m_cfg.client.timeout);
        boost::system::error_code syserr;

        idint::IdInt forwards, reverse;
        Socket::UnderlayEp ulSource;
        std::array<ext::Extension*, 1> hbh = {&reverse};
        auto res = co_await (timer.async_wait(redirect_error(token, syserr))
            || m_socket.recvExtAsync(m_recvBuf, ulSource, hbh, ext::NoExtensions, token));
        if (syserr && syserr != ErrorCondition::Cancelled) co_return syserr;
        if (res.index() == 0) co_return ErrorCode::Timeout;
        auto n = std::get<1>(res);
        if (isError(n)) co_return n.error();
        if (!reverse.isValid()) {
            std::cerr << "Response does not contain ID-INT extension\n";
            co_return ErrorCode::RemoteError;
        }

        // Parse forwards direction from payload
        ReadStream stream(*n);
        StreamError serr;
        hdr::HopByHopOpts hbhHdr;
        if (!hbhHdr.serialize(stream, serr)) {
            std::cerr << "Response payload: " << serr;
            co_return ErrorCode::RemoteError;
        }
        idint::IdInt<>::ReadOpts opts{true};
        if (!forwards.serialize(stream, opts, serr)) {
            std::cerr << "Response payload: " << serr;
            co_return ErrorCode::RemoteError;
        }
        if (!forwards.isValid()) {
            std::cerr << "Response payload does not contain ID-INT report\n";
            co_return ErrorCode::RemoteError;
        }

        // Decode and print
        auto reports = m_cfg.client.noVerify ?
            decode(forwards, reverse, via) : verify(forwards, reverse, via);
        if (isError(reports)) co_return reports.error();

        auto [fwdRep, revRep] = *reports;
        printTelemetry(fwdRep, revRep, via);

        co_return ErrorCode::Ok;
    }

    Maybe<std::pair<idint::IntReport<>, idint::IntReport<>>> decode(
        const idint::IdInt<>& forwards, const idint::IdInt<>& reverse, const Path& via)
    {
        idint::IntReport fwdRep, revRep;
        if (auto err = forwards.decodeUnverified(fwdRep); err) {
            std::cerr << "Decoding reverse path failed\n";
            return Error(err);
        }
        if (auto err = reverse.decodeUnverified(revRep); err) {
            std::cerr << "Decoding reverse path failed\n";
            return Error(err);
        }
        printTelemetry(fwdRep, revRep, via);
        return Error(ErrorCode::Ok);
    }

    Maybe<std::pair<idint::IntReport<>, idint::IntReport<>>> verify(
        const idint::IdInt<>& forwards, const idint::IdInt<>& reverse, const Path& via)
    {
        using namespace std::chrono;
        using Clock = system_clock;
        using TimePoint = system_clock::time_point;

        idint::IntReport fwdRep, revRep;
        idint::VerificationStatus status;
        const auto validAt = Clock::now();
        const auto self = m_socket.localEp().address();

        // The origin AS of an ID-INT stack entry is determined from path
        // metadata in the path the probe was sent on.
        auto metaIf = via.getAttribute<path_meta::Interfaces>(PATH_ATTRIBUTE_INTERFACES);
        if (!metaIf) {
            return Error(ErrorCode::LogicError);
        }
        DecodedScionPath<> decoded(via.firstAS(), via.lastAS());
        if (auto s = ReadStream(via.encoded()); !decoded.serialize(s, NullStreamError)) {
            return Error(ErrorCode::LogicError);
        }

        // Host-Host key shared with the server
        const auto server = m_socket.remoteEp().address();
        auto serverKey = m_keyCache.getHostHostKey(server, self, validAt, [this](auto ...args) {
            return this->fetchHostHostKey(args...);
        });
        if (isError(serverKey)) {
            return Error(serverKey.error());
        }

        // Determines AS and key in forward direction.
        auto hopToKeyFwd = [&, this, hopToIf = idint::hopFieldToInterfaceIdx(decoded)
        ] (std::uint8_t hop, TimePoint validAt) {
            IsdAsn srcAS;
            if (auto i = hopToIf(hop); i < metaIf->data.size()) {
                srcAS = metaIf->data[i].isdAsn;
                auto k = m_keyCache.getASHostKey(srcAS, self, validAt, [this](auto ...args) {
                    return this->fetchASHostKey(args...);
                });
                return std::pair<IsdAsn, Maybe<drkey::Key>>(srcAS, Maybe<drkey::Key>(k));
            }
            return std::pair<IsdAsn, Maybe<drkey::Key>>(srcAS, Error(ErrorCode::NoKey));
        };

        // Determines AS and key in reverse direction, assuming the same path as
        // inforward direction was used.
        auto hopToKeyRev = [&, this, hopToIf = idint::hopFieldToInterfaceIdx(decoded, true)
        ] (std::uint8_t hop, TimePoint validAt) {
            IsdAsn srcAS;
            const auto n = metaIf->data.size();
            if (auto i = hopToIf(hop); i < n) {
                srcAS = metaIf->data[n-i-1].isdAsn;
                auto k = m_keyCache.getASHostKey(srcAS, self, validAt, [this](auto ...args) {
                    return this->fetchASHostKey(args...);
                });
                return std::pair<IsdAsn, Maybe<drkey::Key>>(srcAS, k);
            }
            return std::pair<IsdAsn, Maybe<drkey::Key>>(srcAS, Error(ErrorCode::NoKey));
        };

        status = forwards.verifyAndDecrypt(fwdRep, validAt, m_sourceKey, hopToKeyFwd);
        if (!status) {
            printVerificationError(status, hopToKeyFwd(status.location.hopIndex, validAt).second);
            return Error(status.error);
        }
        status = reverse.verifyAndDecrypt(revRep, validAt, *serverKey, hopToKeyRev);
        if (!status) {
            printVerificationError(status, hopToKeyRev(status.location.hopIndex, validAt).second);
            return Error(status.error);
        }

        return std::make_pair(fwdRep, revRep);
    }

    void printTelemetry(const idint::IntReport<>& fwd, const idint::IntReport<>& rev, const Path& via)
    {
        const auto self = m_socket.localEp().address();
        auto metaIf = via.getAttribute<path_meta::Interfaces>(PATH_ATTRIBUTE_INTERFACES);
        if (!metaIf) return;
        DecodedScionPath<> decoded(via.firstAS(), via.lastAS());
        if (auto s = ReadStream(via.encoded()); !decoded.serialize(s, NullStreamError)) {
            return;
        }

        std::ostringstream out;
        out << std::format("Source: {} Dest: {}\n", m_socket.localEp(), m_socket.remoteEp());
        out << "Path: " << via << '\n';

        out << "\nForward:\n";
        if (fwd.stackFull) {
            out << "Response truncated due to stack limit\n";
        }
        auto hopToASFwd = [&, this, hopToIf = idint::hopFieldToInterfaceIdx(decoded)
        ] (std::uint8_t hop) {
            if (auto i = hopToIf(hop); i < metaIf->data.size()) {
                return metaIf->data[i].isdAsn;
            }
            return IsdAsn();
        };
        printReport(out, fwd, hopToASFwd);

        out << "\nReverse:\n";
        if (fwd.stackFull) {
            out << "Response truncated due to stack limit\n";
        }
        auto hopToASRev = [&, this, hopToIf = idint::hopFieldToInterfaceIdx(decoded, true)
        ] (std::uint8_t hop) {
            const auto n = metaIf->data.size();
            if (auto i = hopToIf(hop); i < n) {
                return metaIf->data[n-i-1].isdAsn;
            }
            return IsdAsn();
        };
        printReport(out, rev, hopToASRev);

        if (m_cfg.client.loop) std::cout << "\033[2J\033[H" << out.str() << std::flush;
        else std::cout << out.str() << std::flush;
    }

    template <typename ostream, typename F>
    void printReport(ostream& out, const idint::IntReport<>& rep, F hopToAS)
    {
        using namespace std::literals;
        using std::uint8_t;

        uint8_t hasNodeId = 0, hasNodeCnt = 0, hasIgPort = 0, hasEgPort = 0;
        uint8_t dataCol[4] = {};
        for (const auto& hop : rep.data) {
            hasNodeId |= hop.hasNodeId();
            hasNodeCnt |= hop.hasNodeCount();
            hasIgPort |=hop.hasIngressPort();
            hasEgPort |= hop.hasEgressPort();
            for (unsigned i = 0; i < 4; ++i) {
                dataCol[i] |= (hop.metadataSize(i) > 0);
            }
        }

        // Header
        out << "  Flags       Source AS";
        if (hasNodeId)  out << " NodeID";
        if (hasNodeCnt) out << "  Count";
        if (hasIgPort)  out << " IgPort";
        if (hasEgPort)  out << " EgPort";
        for (unsigned i = 0; i < 4; ++i) {
            if (dataCol[i]) {
                auto iter = std::ranges::lower_bound(IdIntInstrTable, rep.instructions[i],
                    std::less<idint::Instr>(), [](const auto& x) { return x.id; });
                if (iter != IdIntInstrTable.end() && iter->id == rep.instructions[i]) {
                    dataCol[i] = (std::uint8_t)iter->width;
                    out << std::format("{:>{}}", iter->name, dataCol[i]);
                } else {
                    dataCol[i] = 10;
                    out << std::format("{:>{}}", "UNKNOWN", dataCol[i]);
                }
            }
        }
        out << '\n';

        // Hops
        for (const auto& hop : rep.data) {
            if (hop.isSource())
                out << " S ";
            else
                out << std::format("{:>2} ", hop.hopIndex());

            // Flags
            out << (hop.isIngress()    ? 'I' : '-');
            out << (hop.isEgress()     ? 'E' : '-');
            out << (hop.isAggregate()  ? 'A' : '-');
            out << (hop.wasEncrypted() ? 'C' : '-');

            // ASN
            out << std::format("{:>16}", std::format("{}", hopToAS(hop.hopIndex())));

            // Metadata
            if (hasNodeId) {
                if (hop.hasNodeId())
                    out << std::format(" {:6}", hop.nodeId());
                else
                    out << "      -";
            }
            if (hasNodeCnt) {
                if (hop.hasNodeCount())
                    out << std::format(" {:6}", hop.nodeCount());
                else
                    out << "      -";
            }
            if (hasIgPort) {
                if (hop.hasIngressPort())
                    out << std::format(" {:6}", hop.ingressPort());
                else
                    out << "      -";
            }
            if (hasEgPort) {
                if (hop.hasEgressPort())
                    out << std::format(" {:6}", hop.egressPort());
                else
                    out << "      -";
            }
            for (unsigned i = 0; i < 4; ++i) {
                auto instr = rep.instructions[i];
                if (dataCol[i] > 0) {
                    if (auto x = hop.metadata(i); hop.metadataSize(i))
                        out << std::format("{:>{}}", fmtMetadata(x, instr), dataCol[i]);
                    else
                        out << std::format("{:>{}}", "-", dataCol[i]);
                }
            }
            out << '\n';
        }
    }
};
