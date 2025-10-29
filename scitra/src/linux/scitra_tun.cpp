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

#include "scitra/linux/scitra_tun.hpp"
#include "scitra/linux/sys_net.hpp"

#include <signal.h>

using namespace std::chrono_literals;


// Maximum packet size including headers and headroom.
static constexpr std::size_t PACKET_BUFFER_SIZE = 9000;

// Minimum time a path must be valid in order to be used by active and passive
// flows. Active flows should switch path sooner than passive ones so that when
// scitra is communicating with another instance of itself the active side can
// switch paths first.
static const auto ACTIVE_FLOW_MIN_PATH_LIFE = 60s;
static const auto PASSIVE_FLOW_MIN_PATH_LIFE = 10s;

static PathCacheOptions PATH_CACHE_OPTS = {
    .minAcceptedLifetime = 5min,
    .refreshAtRemaining = 10min,
    .refreshInterval = 30min,
};

/// \brief Returns the minimum overhead SCION adds over IPv6 with either a
/// UDP/IPv4 or UDP/IPv6 underlay.
static std::uint32_t minScionOverhead(bool underlayIsIPv6)
{
    using std::uint32_t;
    constexpr int IPv6_HEADER = 40;   // IPv6 header
    constexpr int IPv4_UNDERLAY = 28; // UDP/IPv4 underlay
    constexpr int IPv6_UNDERLAY = 48; // UDP/IPv6 underlay
    constexpr int SCION_IPv4 = 36;    // SCION header with IPv4 host addresses
    constexpr int SCION_IPv6 = 60;    // SCION header with IPv6 host addresses
    if (!underlayIsIPv6)
        return uint32_t(IPv4_UNDERLAY + SCION_IPv4 - IPv6_HEADER);
    else
        return uint32_t(IPv6_UNDERLAY + SCION_IPv6 - IPv6_HEADER);
};

///////////////
// ScitraTun //
///////////////

ScitraTun::ScitraTun(const Arguments& args)
    : ioCtx(args.threads)
    , signals(ioCtx, SIGINT, SIGTERM)
    , eventTimer(ioCtx)
    , grpcIoCtx()
    , grpcWorkGuard(grpcIoCtx.get_executor())
    , daemon(grpcIoCtx, args.sciond)
    , netDevice(args.publicInterface)
    , tunDevice(args.tunDevice)
    , noDeviceBind(args.noDeviceBind)
    , pathCache(std::make_unique<SharedPathCache>(PATH_CACHE_OPTS))
{
    // Get local AS info from daemon
    if (auto maybe = daemon.rpcAsInfo(IsdAsn()); maybe.has_value()) {
        localAS = *maybe;
    } else {
        throw std::runtime_error(std::format(
            "Error connection to SCION daemon at '{}': {}",
            args.sciond, fmtError(maybe.error())));
    }
    if (auto maybe = daemon.rpcPortRange(); maybe.has_value()) {
        dispPorts = *maybe;
    } else {
        throw std::runtime_error(std::format(
            "Error connection to SCION daemon at '{}': {}",
            args.sciond, fmtError(maybe.error())));
    }

    // Parse public interface address
    if (auto maybe = generic::IPAddress::Parse(args.publicAddress); maybe.has_value()) {
        publicIP = std::move(*maybe);
    } else {
        throw std::runtime_error("Public IP address is invalid");
    }
    if (!publicIP.is4() && !publicIP.isScion()) {
        throw std::runtime_error(
            "Public IP address must either be an IPv4 or SCION-mapped IPv6 address");
    }
    if (auto maybe = mapToIPv6(ScIPAddress(localAS.isdAsn, publicIP)); maybe.has_value()) {
        tunIP = std::move(*maybe);
    } else {
        throw std::runtime_error(std::format("Can't encode {} as IPv6",
            ScIPAddress(localAS.isdAsn, publicIP)));
    }

    // Load path policy
    if (!args.policy.empty()) {
        pathPolicy = std::make_unique<path_policy::PolicySet>();
        auto [ec, msg] = pathPolicy->loadJsonFile(args.policy);
        if (ec) throw std::runtime_error(
            std::format("Error loading policy from '{}': {}", args.policy.string(), msg)
        );
    }

    // Create TUN device
    if (auto tun = createTunQueue(ioCtx, tunDevice); tun.has_value()) {
        tunQueues.emplace_back(std::move(*tun));
    } else {
        throw std::runtime_error(std::format("Can't create TUN interface with name '{}': {}",
            args.tunDevice, tun.error().message()));
    }
    for (int i = 1; i < args.queues; ++i) {
        if (auto tun = createTunQueue(ioCtx, tunDevice); tun.has_value()) {
            tunQueues.emplace_back(std::move(*tun));
        } else {
            throw std::runtime_error(
                std::format("Can't add queue {} to TUN device '{}': {}",
                    i, args.tunDevice, tun.error().message()));
        }
    }

    // Open netlink socket to configure link settings and routing table
    NetlinkRoute netlink;
    if (auto ec = netlink.open(); ec) {
        throw std::runtime_error(
            std::format("Can't open netlink socket: {}", ec.message()));
    }

    // Configure TUN interface MTU
    // By default, the MTU of the TUN interface is set to the maximum IPv6 packet size usable
    // for intra-AS communication with an empty SCION path, so that the effective Path MTU with
    // non-empty paths is always smaller than the interface MTU.
    if (args.mtu) {
        localAS.mtu = args.mtu;
    } else {
        auto mtu = netlink.getInterfaceMTU(netDevice);
        if (isError(mtu)) {
            throw std::runtime_error(
                std::format("Can't get MTU of '{}': {}", netDevice, fmtError(mtu.error())));
        }
        localAS.mtu = std::min(localAS.mtu,
            std::max<std::uint32_t>(1280, *mtu - minScionOverhead(publicIP.is6())));
    }
    if (auto ec = netlink.setInterfaceMTU(tunDevice, localAS.mtu); ec) {
        throw std::runtime_error(
            std::format("Can't set MTU of '{}': {}", netDevice, fmtError(ec)));
    }

    // Configure TUN IP and Route
    if (auto ec = netlink.setInterfaceState(tunDevice, true); ec) {
        throw std::runtime_error(
            std::format("Can't bring TUN interface up: {}", ec.message()));
    }
    if (auto ec = netlink.addAddress(tunIP, 128, tunDevice); ec) {
        throw std::runtime_error(
            std::format("Adding SCION-mapped address '{}' to '{}' failed: {}",
                tunIP, tunDevice, ec.message()));
    }
    auto prefix = generic::IPAddress::MakeIPv6(0xfcull << 56, 0);
    if (auto ec = netlink.addRoute(prefix, 8, tunDevice); ec) {
        throw std::runtime_error(
            std::format("Adding SCION-mapped IPv6 prefix route failed: {}", ec.message()));
    }

    // Link SCMP handlers
    pmtu = std::make_unique<PathMtuDiscoverer<>>(localAS.mtu);
    pathCache->setNextScmpHandler(pmtu.get());
}

void ScitraTun::run(const Arguments& args)
{
    // Start signal handler
    asio::co_spawn(ioCtx, signalHandler(), asio::detached);

    // Start timer
    asio::co_spawn(ioCtx, tick(), asio::detached);

    // Start a coroutine for every queue of the TUN device
    for (TunQueue& queue : tunQueues) {
        asio::co_spawn(ioCtx, translateIPtoScion(queue), asio::detached);
    }

    // Open dispatcher socket and start a corresponding coroutine
    if (args.enabledDispatch) {
        if (auto res = openSocket(scion::scitra::DISPATCHER_PORT, true); scion::isError(res)) {
            throw std::runtime_error(std::format("Error opening socket at port {}: {}\n",
                scion::scitra::DISPATCHER_PORT, scion::fmtError(res.error())));
        }
    }

    // Open permanent sockets and start corresponding coroutines
    for (std::uint16_t port : args.ports) {
        if (port != scion::scitra::DISPATCHER_PORT) {
            if (auto res = openSocket(port, true); scion::isError(res)) {
                throw std::runtime_error(std::format("Error opening socket at port {}: {}\n",
                    port, scion::fmtError(res.error())));
            }
        }
    }

    // Start worker threads after all queues and static sockets are ready.
    threads.reserve(args.threads + 1);
    for (int i = 0; i < args.threads; ++i) {
        threads.emplace_back([this] {
            sigset_t sigset;
            sigemptyset(&sigset);
            sigaddset(&sigset, SIGINT);
            sigaddset(&sigset, SIGTERM);
            if (pthread_sigmask(SIG_UNBLOCK, &sigset, nullptr))
                throw std::system_error(errno, std::generic_category());
            ioCtx.run();
        });
    }

    // Run gRPC context on its own thread
    threads.emplace_back([this] {
        grpcIoCtx.run();
    });
}

ScitraTun::~ScitraTun()
{
    stop();
    join();
}

void ScitraTun::stop()
{
    shouldExit = true;
    grpcWorkGuard.reset();
    grpcIoCtx.stop();
    std::unique_lock lock(socketMutex);
    for (auto& s: sockets)
        s.second->close();
    for (auto& queue : tunQueues)
        queue.close();
    eventTimer.cancel();
    signals.cancel();
}

void ScitraTun::join()
{
    for (auto& thread : threads)
        thread.join();
    threads.clear();
}

Maybe<std::shared_ptr<Socket>> ScitraTun::openSocket(std::uint16_t port, bool permanent)
{
    std::unique_lock lock(socketMutex);
    if (shouldExit) return Error(ScitraError::Exiting);
    if (auto i = sockets.find(port); i != sockets.end()) {
        return i->second;
    }
    auto socket = std::make_shared<Socket>(ioCtx, port, permanent);
    if (auto ip = generic::toUnderlay<asio::ip::address>(publicIP); ip) {
        if (auto ec = socket->open(*ip, noDeviceBind ? "" : netDevice); ec) {
            return Error(ec);
        }
    } else {
        return Error(ip.error());
    }
    auto [_, ok] = sockets.insert(std::make_pair(port, socket));
    if (!ok) return Error(ScitraError::LogicError);
    asio::co_spawn(ioCtx, translateScionToIP(socket), asio::detached);
    return socket;
}

std::shared_ptr<Socket> ScitraTun::getSocket(std::uint16_t port)
{
    std::shared_lock lock(socketMutex);
    // if (port != DISPATCHER_PORT && dispPorts.first <= port && port <= dispPorts.second) {
        // In "dispatched" port range, use application port directly
        if (auto i = sockets.find(port); i != sockets.end()) {
            return i->second;
        } else {
            // Attempt to open a temporary socket
            lock.unlock();
            if (auto s = openSocket(port, false); s.has_value()) {
                return *s;
            } else {
                std::cerr << std::format("Can't open socket at port {}: {}\n",
                    port, fmtError(s.error()));
                return nullptr;
            }
        }
    // } else if (auto dispatcher = sockets.find(DISPATCHER_PORT); dispatcher != sockets.end()) {
    //     // Outside of "dispatched ports", fall back to dispatcher port
    //     return dispatcher->second;
    // }
    return nullptr;
}

void ScitraTun::closeSocket(std::uint16_t port)
{
    std::unique_lock lock(socketMutex);
    if (auto i = sockets.find(port); i != sockets.end()) {
        i->second->close();
        i = sockets.erase(i);
    }
}

void ScitraTun::maintainFlowsAndSockets()
{
    using namespace std::chrono;
    static const auto SOCKET_TIMEOUT = seconds(120);
    static const auto PMTU_TIMEOUT = hours(1);

    auto mySockets = getSocketInodes(32);
    std::ranges::sort(mySockets);
    auto udpSockets = getSocketsUdp6(32);
    auto tcpSockets = getSocketsTcp6(32);

    std::scoped_lock lock{socketMutex, flowMutex};

    // Clear old PMTU cache entries
    pmtu->clear(steady_clock::now() - PMTU_TIMEOUT);

    // Advance flow states
    FlowState state = FlowState::CLOSED;
    for (auto i = flows.begin(); i != flows.end();) {
        i->second->lock().getState(state).tick();
        if (state == FlowState::CLOSED)
            i = flows.erase(i);
        else
            ++i;
    }

    // Maintain up-to-date paths.
    for (auto&& [id, flow] : flows) {
        if (flow->getType() == FlowType::Active) {
            pathCache->prefetch(id.src.isdAsn(), id.dst.isdAsn(),
            [this] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) {
                return queryPaths(cache, src, dst);
            });
        }
    }

    // Close all sockets that aren't used anymore.
    auto now = std::chrono::steady_clock::now();
    for (auto i = sockets.begin(); i != sockets.end();) {
        auto& socket = i->second;
        auto localPort = socket->port();
        if (socket->permanent()) {
            ++i;
            continue;
        }
        // Keep socket if there has been outgoing traffic recently.
        if (now - socket->lastUsed() > SOCKET_TIMEOUT) {
            ++i;
            continue;
        }
        // Keep socket if there is a TCP socket using the same port.
        // Ignores listening TCP sockets as server should use permanent
        // port forwarding.
        auto tcp = std::ranges::find_if(tcpSockets, [&] (const SocketInfo& s) {
            if (std::ranges::binary_search(mySockets, s.inode))
                return false;
            if (s.localPort == localPort && s.state != TCP_LISTEN)
                return s.localAddr.isUnspecified() || s.localAddr == tunIP;
            return false;
        });
        if (tcp != tcpSockets.end()) {
            ++i;
            continue;
        }
        // Keep socket if there is a connected UDP socket using the same
        // port.
        auto udp = std::ranges::find_if(udpSockets, [&] (const SocketInfo& s) {
            if (std::ranges::binary_search(mySockets, s.inode))
                return false;
            if (s.localPort == localPort && s.remoteAddr.isScion())
                return s.localAddr.isUnspecified() || s.localAddr == tunIP;
            return false;
        });
        if (udp != udpSockets.end()) {
            ++i;
            continue;
        }
        socket->close();
        i = sockets.erase(i);
        for (auto j = flows.begin(); j != flows.end(); ++j) {
            if (j->first.src.port() == localPort) {
                j->second->lock().close();
            }
        }
    }
}

asio::awaitable<void> ScitraTun::signalHandler()
{
    constexpr auto token = boost::asio::as_tuple(boost::asio::use_awaitable);
    while (!shouldExit) {
        auto [ec, signal] = co_await signals.async_wait(token);
        if (ec) {
            if (ec == std::errc::operation_canceled) {
                co_return;
            } else {
                std::cerr << std::format("Signal handler error: {}\n", fmtError(ec));
                std::exit(EXIT_FAILURE);
            }
        }
        if (signal == SIGINT || signal == SIGTERM) {
            if (signal == SIGINT)
                std::cerr << "Got SIGINT, stopping..." << std::endl;
            else
                std::cerr << "Got SIGTERM, stopping..." << std::endl;
            stop();
            co_return;
        }
    }
}

asio::awaitable<std::error_code> ScitraTun::tick()
{
    constexpr auto token = boost::asio::as_tuple(boost::asio::use_awaitable);
    while (!shouldExit) {
        eventTimer.expires_after(std::chrono::seconds(1));
        auto [ec] = co_await eventTimer.async_wait(token);
        if (ec) co_return ec;
        maintainFlowsAndSockets();
    }
}

asio::awaitable<std::error_code> ScitraTun::translateIPtoScion(TunQueue& tun)
{
    using std::uint8_t;
    using std::uint16_t;
    PacketBuffer pkt{std::pmr::vector<std::byte>(PACKET_BUFFER_SIZE)};

    while (tun.isOpen()) {
        auto ec = co_await tun.recvPacket(pkt);
        if (ec) {
            if (ec == std::errc::bad_file_descriptor || ec == std::errc::operation_canceled) {
                break;
            } else {
                SCION_DEBUG_PRINT("Error: " << fmtError(ec) << '\n');
                continue;
            }
        }

        std::shared_ptr<Flow> flow = nullptr;
        auto [verdict, port, nextHop] = translateEgress(pkt, publicIP,
            [&] (const ScIPAddress& src, const ScIPAddress& dst,
                uint16_t sport, uint16_t dport, hdr::ScionProto proto, uint8_t tc)
            {
                PathPtr path;
                std::uint16_t mtu = 0;
                ScIPAddress localSrc(localAS.isdAsn, src.host());
                flow = getFlow(FlowID(localSrc, dst, sport, dport, proto), FlowType::Active);
                flow->lock().getPath(path);

                bool expiresSoon = false;
                if (path) {
                    auto ttl = path->expiry() - std::chrono::utc_clock::now();
                    if (flow->getType() == FlowType::Active)
                        expiresSoon = ttl < ACTIVE_FLOW_MIN_PATH_LIFE;
                    else
                        expiresSoon = ttl < PASSIVE_FLOW_MIN_PATH_LIFE;
                }

                if (!path || path->broken() || expiresSoon) {
                    auto maybe = selectPath(src, dst, sport, dport, proto, tc);
                    if (maybe.has_value() && *maybe) {
                        flow->lock().setPath(*maybe);
                        mtu = pmtu->getMtu(dst.host(), **maybe, std::chrono::steady_clock::now());
                    }
                    return std::make_pair(maybe, mtu);
                }
                mtu = pmtu->getMtu(dst.host(), *path, std::chrono::steady_clock::now());
                return std::make_pair(Maybe<PathPtr>(std::move(path)), mtu);
            }
        );

        if (verdict == Verdict::Pass) {
            if (auto socket = getSocket(port); socket) {
                assert(flow);
                flow->lock().updateState(pkt).countEgress(1, pkt.payload().size());
                auto nh = generic::toUnderlay<asio::ip::udp::endpoint>(nextHop);
                if (!nh.has_value()) continue; // this should never happen
                auto ec = co_await socket->sendPacket(pkt, *nh);
                if (ec) std::cerr << std::format("Error sending packet to next hop '{}': {}\n",
                    *nh, fmtError(ec));
            }
        } else if (verdict == Verdict::Return) {
            auto ec = co_await tun.sendPacket(pkt);
            if (ec) std::cerr << std::format("Error sending packet to TUN: {}\n", fmtError(ec));
        }
    }
    co_return ScitraError::Cancelled;
}

asio::awaitable<std::error_code> ScitraTun::translateScionToIP(std::shared_ptr<Socket> socket)
{
    PacketBuffer pkt{std::pmr::vector<std::byte>(PACKET_BUFFER_SIZE)};
    asio::ip::udp::endpoint from;

    while (socket->isOpen()) {
        auto ec = co_await socket->recvPacket(pkt, from);
        if (ec) {
            if (ec == std::errc::bad_file_descriptor || ec == std::errc::operation_canceled) {
                break;
            } else {
                std::cerr << "Error: " << fmtError(ec) << '\n';
                continue;
            }
        }

        // Packet Validation: Local socket port must match inner L4 header
        // destination port if not using the dispatcher socket.
        if (socket->port() != DISPATCHER_PORT) {
            if (pkt.l4DPort() != socket->port()) continue;
        }
        // Packet Validation: AS-internal traffic source must match source
        // host address in the SCION header.
        if (pkt.path.empty()) {
            auto src = generic::toGenericEp(from);
            if (pkt.sci.src.host() != src.host()) continue;
            if (pkt.l4SPort() != src.port()) continue;
        }

        // Handle SCMP
        if (pkt.l4Valid == PacketBuffer::L4Type::SCMP) {
            pathCache->handleScmp(pkt.sci.src, pkt.path, pkt.scmp.msg, pkt.payload());
        }

        // Attempt translation
        auto verdict = translateIngress(pkt, tunIP,
            [&] (const hdr::SCION& sci, const RawPath& rp)
            {
                RawPath copy = rp;
                copy.reverseInPlace();
                return pmtu->getMtu(sci.dst.host(), copy, std::chrono::steady_clock::now());
            }
        );
        if (verdict == Verdict::Pass) {
            auto fl = getFlow(FlowID(Igr, pkt), FlowType::Passive);
            if (fl->getType() == FlowType::Passive && !pkt.path.reverseInPlace()) {
                fl->lock()
                    .updatePassivePath(pkt.path, generic::toGenericEp(from))
                    .updateState(pkt).countIngress(1, pkt.payload().size());
            } else {
                fl->lock().updateState(pkt).countIngress(1, pkt.payload().size());
            }
            auto queue = socket->port() % tunQueues.size();
            auto ec = co_await tunQueues[queue].sendPacket(pkt);
            if (ec) std::cerr << std::format("Error sending packet to TUN (queue {}): {}\n",
                queue, fmtError(ec));
        }
    }
}

std::error_code ScitraTun::queryPaths(SharedPathCache& cache, IsdAsn src, IsdAsn dst)
{
    using namespace scion::daemon;
    asio::co_spawn(grpcIoCtx, [this, src, dst] () -> asio::awaitable<void> {
        std::vector<PathPtr> paths;
        auto flags = PathReqFlags::Refresh | PathReqFlags::AllMetadata;
        co_await daemon.rpcPathsAsync(src, dst, flags, std::back_inserter(paths));
        pathCache->store(src, dst, paths);
    }, asio::detached);
    return ErrorCode::Pending;
}

Maybe<PathPtr> ScitraTun::selectPath(
    const ScIPAddress& src, const ScIPAddress& dst,
    std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc)
{
    auto paths = pathCache->lookup(localAS.isdAsn, dst.isdAsn(),
        [this] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) {
            return queryPaths(cache, src, dst);
        }
    );

    if (paths) {
        if (pathPolicy) {
            auto filtered = pathPolicy->apply(
                ScIPEndpoint(src, sport), ScIPEndpoint(dst, dport),
                proto, tc, *paths);
            paths->resize(filtered.size());
        }
        if (paths->empty()) return nullptr; // no matching paths
        return paths->front(); // just return the first matching path
    } else {
        if (paths.error() == ErrorCondition::Pending)
            return Error(paths.error()); // paths not ready yet
        else
            return nullptr; // no path
    }
}
