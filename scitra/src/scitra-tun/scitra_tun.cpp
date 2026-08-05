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

#include "scitra/crypto.hpp"
#include "scitra/scitra-tun/debug.hpp"
#include "scitra/scitra-tun/scitra_tun.hpp"
#include "scitra/scitra-tun/service.hpp"
#include "scitra/scitra-tun/sys_net.hpp"

#include <spdlog/spdlog.h>

#include <ranges>
#include <signal.h>

using namespace std::chrono_literals;


// Maximum packet size including headers and headroom.
static constexpr std::size_t PACKET_BUFFER_SIZE = 9000;
// Minimum safe MTU for SCION with an IPv4 underlay.
static constexpr std::uint16_t SAFE_MTU_IPV4 = 576 - 28;
// Minimum safe MTU for SCION with an IPv6 underlay.
static constexpr std::uint16_t SAFE_MTU_IPV6 = 1280 - 48;
// Size of the UDP/IPv4 underlay in bytes.
static constexpr int IPv4_UNDERLAY_SIZE = 28;
// Size of the UDP/IPv6 underlay in bytes.
static constexpr int IPv6_UNDERLAY_SIZE = 48;

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
static int minScionOverhead(bool underlayIsIPv6)
{
    constexpr int IPv6_HEADER = 40; // IPv6 header
    constexpr int SCION_IPv4 = 36;  // SCION header with IPv4 host addresses
    constexpr int SCION_IPv6 = 60;  // SCION header with IPv6 host addresses
    if (!underlayIsIPv6)
        return IPv4_UNDERLAY_SIZE + SCION_IPv4 - IPv6_HEADER;
    else
        return IPv6_UNDERLAY_SIZE + SCION_IPv6 - IPv6_HEADER;
};

///////////////
// ScitraTun //
///////////////

ScitraTun::ScitraTun(const Arguments& args)
    : ioCtx(args.threads)
    , signals(ioCtx)
    , eventTimer(ioCtx)
    , grpcIoCtx()
    , grpcWorkGuard(grpcIoCtx.get_executor())
    , daemon(grpcIoCtx, args.sciond)
    , enableScmpDispatch(args.enableScmpDispatch)
    , staticPorts(args.ports)
    , configQueues(args.queues)
    , configThreads(args.threads)
    , netDevice(args.publicInterface)
    , tunDevice(args.tunDevice)
    , policyFile(args.policy)
    , pathCache(std::make_unique<SharedPathCache>(PATH_CACHE_OPTS))
{
    // Signals handled by signalHandler()
    signals.add(SIGINT);
    signals.add(SIGTERM);
    signals.add(SIGHUP);
    signals.add(SIGUSR1);
    signals.add(SIGUSR2);

    // Get local AS info from daemon
    if (auto maybe = daemon.rpcAsInfo(IsdAsn()); maybe.has_value()) {
        localAS = *maybe;
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
        mappedIP = std::move(*maybe);
    } else {
        throw std::runtime_error(std::format("Can't encode {} as IPv6",
            ScIPAddress(localAS.isdAsn, publicIP)));
    }

    // Determine TUN address
    if (!args.tunAddress.empty()) {
        if (auto maybe = generic::IPAddress::Parse(args.tunAddress); maybe.has_value()) {
            tunIP = std::move(*maybe);
        } else {
            throw std::runtime_error("Tunnel IP address is invalid");
        }
    } else {
        tunIP = mappedIP;
    }

    // Parse extra addresses
    extraIPs.reserve(args.extraAddresses.size());
    for (auto& raw : args.extraAddresses) {
        if (auto maybe = generic::IPAddress::Parse(raw); maybe.has_value()) {
            extraIPs.push_back(std::move(*maybe));
        } else {
            throw std::runtime_error(std::format("Address {} is invalid", raw));
        }
    }

    // Load path policy
    if (!args.policy.empty()) {
        if (auto ec = loadPathPolicy(policyFile); ec) {
            throw std::runtime_error(std::format("Loading policy from '{}' failed: {}",
                policyFile.string(), fmtError(ec)));
        }
    }

    // Create TUN device
    if (auto tun = createTunQueue(tunDevice); tun.has_value()) {
        tunQueues.emplace_back(std::move(*tun));
    } else {
        throw std::runtime_error(std::format("Can't create TUN interface with name '{}': {}",
            args.tunDevice, tun.error().message()));
    }
    for (int i = 1; i < args.queues; ++i) {
        if (auto tun = createTunQueue(tunDevice); tun.has_value()) {
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
    const auto underlaySize = publicIP.is6() ? IPv6_UNDERLAY_SIZE : IPv4_UNDERLAY_SIZE;
    if (args.underlayMtu) {
        const auto scionMtu = std::max(0, args.underlayMtu - underlaySize);
        spdlog::info("Replacing SCION MTU {} from daemon with {}", localAS.mtu, scionMtu);
        localAS.mtu = scionMtu;
    }
    auto publicMtu = netlink.getInterfaceMTU(netDevice);
    if (isError(publicMtu)) {
        throw std::runtime_error(
            std::format("Can't get MTU of '{}': {}", netDevice, fmtError(publicMtu.error())));
    }
    int tunMtu = args.tunMtu;
    if (tunMtu <= 0) {
        // By default, the MTU of the TUN interface is set to the maximum IPv6 packet size usable
        // for intra-AS communication with an empty SCION path, so that the effective Path MTU with
        // non-empty paths is always smaller than the interface MTU.
        tunMtu = std::min((int)localAS.mtu + underlaySize, (int)*publicMtu);
        tunMtu -= minScionOverhead(publicIP.is6());
    }
    tunMtu = std::max(tunMtu, 1280); // can't set the MTU lower then the minimum for IPv6
    spdlog::info("TUN MTU = {} ({} SCION MTU, {} public interface)",
        tunMtu, localAS.mtu, *publicMtu);
    if (auto ec = netlink.setInterfaceMTU(tunDevice, (std::uint32_t)tunMtu); ec) {
        throw std::runtime_error(
            std::format("Can't set MTU of '{}': {}", tunDevice, fmtError(ec)));
    }
    localAS.mtu = std::min(localAS.mtu, (std::uint32_t)(tunMtu + underlaySize));

    // Configure TUN IP and Route
    if (auto ec = netlink.setInterfaceState(tunDevice, true); ec) {
        throw std::runtime_error(
            std::format("Can't bring TUN interface up: {}", ec.message()));
    }
    if (auto ec = netlink.addAddress(tunIP, 128, tunDevice); ec) {
        throw std::runtime_error(
            std::format("Adding {} to TUN interface failed: {}", tunIP, ec.message()));
    } else {
        spdlog::info("Added primary IP {} to TUN interface", tunIP);
    }
    for (auto& ip : extraIPs) {
        if (auto ec = netlink.addAddress(ip, 128, tunDevice); ec) {
            throw std::runtime_error(
                std::format("Adding {} to TUN interface failed: {}", ip, ec.message()));
        } else {
            spdlog::info("Added {} to TUN interface", ip);
        }
    }

    // Add route to fc00::/8 with TUN IP as the preferred source, so sockets bound to 0::/0 will
    // use the correct source IP even when extra IPs are present.
    auto prefix = generic::IPAddress::MakeIPv6(0xfcull << 56, 0);
    constexpr NetlinkRoute::PrefixLen plen = 8;
    if (auto ec = netlink.addRoute(NetlinkRoute::TABLE_MAIN, prefix, plen, tunDevice, &tunIP); ec) {
        // On slow systems, it can take a while for tunIP to become available after assignment.
        constexpr int ADD_ROUTE_RETRIES = 2;
        for (int i = 0; i < ADD_ROUTE_RETRIES; ++i) {
            if (ec == std::errc::invalid_argument || ec == std::errc::address_not_available) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                spdlog::debug("Retrying netlink.addRoute");
                ec = netlink.addRoute(NetlinkRoute::TABLE_MAIN, prefix, plen, tunDevice, &tunIP);
            } else {
                break;
            }
        }
        if (ec) throw std::runtime_error(
            std::format("Adding SCION-mapped IPv6 prefix route failed: {}", ec.message()));
    }
    spdlog::info("Added route to {}/{} via {} src {}", prefix, plen, tunDevice, tunIP);

    // Link SCMP handlers
    pmtu = std::make_unique<PathMtuDiscoverer<>>(localAS.mtu);
    pathCache->setNextScmpHandler(pmtu.get());
}

void ScitraTun::run()
{
    shouldExit = false;

    // Start signal handler
    asio::co_spawn(ioCtx, signalHandler(), asio::detached);

    // Start timer
    asio::co_spawn(ioCtx, tick(), asio::detached);

    // Open dispatcher socket and start a corresponding coroutine
    if (enableScmpDispatch) {
        if (auto res = openSocket(scion::scitra::DISPATCHER_PORT, true); scion::isError(res)) {
            throw std::runtime_error(std::format("Error opening socket at port {}: {}\n",
                scion::scitra::DISPATCHER_PORT, scion::fmtError(res.error())));
        }
    }

    // Open persistent sockets and start corresponding coroutines
    for (std::uint16_t port : staticPorts) {
        if (port != scion::scitra::DISPATCHER_PORT) {
            if (auto res = openSocket(port, true); scion::isError(res)) {
                throw std::runtime_error(std::format("Error opening socket at port {}: {}\n",
                    port, scion::fmtError(res.error())));
            }
        }
    }

    // Start worker threads after all queues and static sockets are ready
    threads.reserve(configThreads + configQueues + 1);
    for (std::uint32_t i = 0; i < configThreads; ++i) {
        threads.emplace_back([this] {
            sigset_t sigset;
            sigfillset(&sigset);
            if (pthread_sigmask(SIG_UNBLOCK, &sigset, nullptr))
                throw std::system_error(errno, std::generic_category());
            ioCtx.run();
        });
        pthread_setname_np(threads.back().native_handle(), std::format("worker{}", i).c_str());
    }

    // Start a thread for every queue of the TUN device
    for (auto [i, queue] : std::ranges::enumerate_view(tunQueues)) {
        threads.emplace_back([this] (TunQueue& queue) {
            translateIPtoScion(queue);
        }, std::ref(queue));
        pthread_setname_np(threads.back().native_handle(), std::format("tunQ{}", i).c_str());
    }

    // Run gRPC context on its own thread
    threads.emplace_back([this] {
        grpcIoCtx.run();
    });
    pthread_setname_np(threads.back().native_handle(), "grpcIoCtx");
}

ScitraTun::~ScitraTun()
{
    stop();
    join();
}

void ScitraTun::stop()
{
    service::setServiceStatus(service::Status::StopPending);
    shouldExit = true;
    grpcWorkGuard.reset();
    grpcIoCtx.stop();
    std::unique_lock lock(socketMutex);
    for (auto& s: sockets)
        s.second->close();
    for (auto& queue : tunQueues)
        queue.cancel();
    eventTimer.cancel();
    signals.cancel();
}

void ScitraTun::join()
{
    for (auto& thread : threads)
        thread.join();
    threads.clear();
}

std::vector<PathPtr> ScitraTun::getPaths(const FlowID& flowid, std::uint8_t tc) const
{
    auto paths = pathCache->lookupCached(flowid.src.isdAsn(), flowid.dst.isdAsn());
    if (auto policy = pathPolicy.load()) {
        auto filtered = policy->apply(flowid.src, flowid.dst, flowid.proto, tc, paths);
        paths.resize(filtered.size());
    }
    return paths;
}

void ScitraTun::overrideFlowPath(const FlowID& flowid, PathPtr path)
{
    std::lock_guard lock(flowMutex);
    if (auto i = flows.find(flowid); i != flows.end()) {
        if (i->second->getType() == FlowType::Active && !i->second->isMultipath())
            i->second->lock().setPath(path);
    }
}

void ScitraTun::removeFlow(const FlowID& flowid)
{
    std::lock_guard lock(flowMutex);
    spdlog::debug("Remove flow {}", flowid);
    flows.erase(flowid);
}

void ScitraTun::refreshPaths(IsdAsn dst)
{
    pathCache->prefetch(localAS.isdAsn, dst,
    [this] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) {
        return beginPathQuery(cache, src, dst);
    }, true);
}

std::vector<FlowInfo> ScitraTun::exportFlows(bool resetCounters) const
{
    std::vector<FlowInfo> out;
    out.reserve(flows.size());

    std::scoped_lock lock{socketMutex, flowMutex};
    FlowInfo::FlagSet flags = {};
    FlowState state;
    std::uint8_t tc;
    std::uint32_t token = 0;
    FlowCounters counters;
    std::chrono::steady_clock::time_point lastUsed;
    PathPtr path;

    for (auto& [id, flow] : flows) {
        if (flow->isMultipath()) flags |= FlowInfo::Flags::Multipath;
        auto fl = flow->lock();
        fl.getState(state);
        if (state > FlowState::CLOSED_WAIT) {
            fl.getTrafficClass(tc).getMptcpToken(token).getLastUpdate(lastUsed)
                .getCounters(counters).getPath(path);
            if (resetCounters) fl.resetCounters();
            out.emplace_back(id, flags, flow->getType(), state, tc, flow->getLocalEp(), token,
                counters, lastUsed, path, path ? pmtu->getMtu(id.dst.host(), *path) : 0);
        }

        if (flags[FlowInfo::Flags::Multipath]) {
            fl.applyToSubflows([&] (auto& sf) {
                auto sfl = sf.lock();
                sfl.getState(state).getTrafficClass(tc).getMptcpToken(token).getLastUpdate(lastUsed)
                   .getCounters(counters).getPath(path);
                if (resetCounters) sfl.resetCounters();
                out.emplace_back(id, flags, flow->getType(), state, tc, sf.getLocalEp(), token,
                counters, lastUsed, path, path ? pmtu->getMtu(id.dst.host(), *path) : 0);
            });
        }
    }
    return out;
}

std::error_code ScitraTun::loadPathPolicy(const std::filesystem::path& path)
{
    if (path.empty()) return ErrorCode::FileNotFound;
    auto policy = std::make_shared<path_policy::PolicySet>();
    auto [ec, msg] = policy->loadJsonFile(path);
    if (ec) {
        spdlog::error("Error loading policy from '{}': {}", path.string(), msg);
        return ec;
    }
    pathPolicy.store(policy);
    policyFile = path;
    return ErrorCode::Ok;
}

std::error_code ScitraTun::reloadPathPolicy()
{
    auto ec = loadPathPolicy(policyFile);
    if (!ec) spdlog::info("Path policy reloaded");
    return ec;
}

Maybe<std::shared_ptr<Socket>> ScitraTun::openSocket(std::uint16_t port, bool persistent)
{
    std::unique_lock lock(socketMutex);
    spdlog::debug("Open socket {} (persistent: {})", port, persistent);
    if (shouldExit) return Error(ScitraError::Exiting);
    if (auto i = sockets.find(port); i != sockets.end()) {
        return i->second;
    }
    auto socket = std::make_shared<Socket>(ioCtx, port, persistent);
    if (auto ip = generic::toUnderlay<asio::ip::address>(publicIP); ip) {
        if (auto ec = socket->open(*ip); ec) {
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

std::shared_ptr<Flow> ScitraTun::getFlowEgress(
    const PacketBuffer& pkt, FlowID& id, const generic::IPEndpoint& localEp)
{
    std::shared_ptr<Flow> flow;
    std::lock_guard lock(flowMutex);

    // Map MPTCP subflows to SCION flow
    bool subflowSyn = false;
    uint32_t receiverToken = 0;
    if (!extraIPs.empty() && pkt.l4Valid == PacketBuffer::L4Type::TCP) {
        if (pkt.tcp.optMask.MpJoin && pkt.tcp.options.mpJoin.content.index() == 0) {
            // New subflow SYN, demultiplex by receiver token
            subflowSyn = true;
            receiverToken = std::get<0>(pkt.tcp.options.mpJoin.content).receiverToken;
            if (auto i = mpTokenMap.find(receiverToken); i != mpTokenMap.end()) {
                flow = i->second;
                auto sport = flow->getLocalEp().port(); // remap port to existing flow
                mpPortRemap[localEp] = sport;
                id.src = ScIPEndpoint(id.src.address(), sport);
            }
        } else if (localEp.host() != tunIP) {
            // Packet comes from one of the extra IPs, might need source port remapping
            if (auto i = mpPortRemap.find(localEp); i != mpPortRemap.end()) {
                id.src = ScIPEndpoint(id.src.address(), i->second);
            }
        }
    }

    if (!flow) {
        flow = flows[id];
        if (!flow) {
            spdlog::debug("New {} flow {}", toString(FlowType::Active), id);
            flow = Flow::Create(localEp, FlowType::Active);
            flows[id] = flow;
        }
    }

    // Learn the receiver token for additional subflows
    if (subflowSyn) {
        spdlog::debug("MPTCP connection {} has receiver token {:08x}", id, receiverToken);
        mpTokenMap[receiverToken] = flow;
        flow->lock().setMptcpToken(receiverToken);
    } else if (pkt.l4Valid == PacketBuffer::L4Type::TCP && pkt.tcp.optMask.MpCapable) {
        auto& cap = pkt.tcp.options.mpCap;
        if (cap.fieldMask.receiverKey) {
            receiverToken = scion::scitra::sha256_trunc(cap.receiverKey);
            spdlog::debug("MPTCP connection {} has receiver token {:08x} (key {})",
                id, receiverToken, cap.receiverKey);
            mpTokenMap[receiverToken] = flow;
            flow->lock().setMptcpToken(receiverToken);
        }
    }

    return flow;
}

// Get an existing flow or create a new one. If a new flow is created
// it will be of type `type` with local IP endpoint `localIP`.
std::shared_ptr<Flow> ScitraTun::getFlowIngress(
    const FlowID& id, const generic::IPEndpoint& localEp)
{
    std::lock_guard lock(flowMutex);
    auto flow = flows[id];
    if (!flow) {
        spdlog::debug("New {} flow {}", toString(FlowType::Passive), id);
        flow = Flow::Create(localEp, FlowType::Passive);
        flows[id] = flow;
    }
    return flow;
}

// Find an existing flow. Returns nullptr, if the flow is not found.
std::shared_ptr<Flow> ScitraTun::findFlow(const FlowID& id)
{
    std::lock_guard lock(flowMutex);
    auto flow = flows.find(id);
    if (flow == flows.end()) return nullptr;
    return flow->second;
}

std::shared_ptr<Socket> ScitraTun::getSocket(std::uint16_t port)
{
    std::shared_lock lock(socketMutex);
    if (port == DISPATCHER_PORT && !enableScmpDispatch) {
        return nullptr;
    }
    if (auto i = sockets.find(port); i != sockets.end()) {
        return i->second;
    } else {
        // Attempt to open a temporary socket
        lock.unlock();
        if (auto s = openSocket(port, false); s.has_value()) {
            return *s;
        } else {
            spdlog::error("Can't open socket at port {}: {}", port, fmtError(s.error()));
            return nullptr;
        }
    }
    return nullptr;
}

void ScitraTun::closeSocket(std::uint16_t port)
{
    std::unique_lock lock(socketMutex);
    spdlog::debug("Close socket {}", port);
    if (auto i = sockets.find(port); i != sockets.end()) {
        i->second->close();
        i = sockets.erase(i);
    }
}

void ScitraTun::maintainFlowsAndSockets()
{
    using namespace std::chrono;
    using scion::hdr::ScionProto;
    static const auto SOCKET_TIMEOUT = seconds(60);
    static const auto PMTU_TIMEOUT = hours(1);

    auto mySockets = getSocketInodes(32);
    std::ranges::sort(mySockets);
    auto udpSockets = getSocketsUdp6(32);
    auto tcpSockets = getSocketsTcp6(32);

    std::scoped_lock lock{socketMutex, flowMutex};
    const auto now = std::chrono::steady_clock::now();

    // Clear old PMTU cache entries
    pmtu->clear(steady_clock::now() - PMTU_TIMEOUT);

    // Advance flow states
    FlowState state = FlowState::CLOSED;
    for (auto i = flows.begin(); i != flows.end();) {
        if (i->second->isMultipath()) {
            i->second->lock().removeSubflows([&] (Flow& sf) {
                sf.lock().getState(state).tick(now);
                if (state == FlowState::CLOSED) {
                    spdlog::debug("Remove subflowflow {} (bound to {})", i->first, sf.getLocalEp());
                    mpPortRemap.erase(sf.getLocalEp());
                    return true;
                }
                return false;
            });
        }
        std::uint32_t token = 0;
        i->second->lock().getMptcpToken(token).getState(state).tick(now);
        if (state == FlowState::CLOSED) {
            spdlog::debug("Remove flow {}", i->first);
            mpTokenMap.erase(token);
            i = flows.erase(i);
        } else {
            ++i;
        }
    }

    // Maintain up-to-date paths
    for (auto&& [id, flow] : flows) {
        if (flow->getType() == FlowType::Active) {
            pathCache->prefetch(id.src.isdAsn(), id.dst.isdAsn(),
            [this] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) {
                return beginPathQuery(cache, src, dst);
            });
        }
    }

    // Close all sockets that aren't used anymore.
    for (auto i = sockets.begin(); i != sockets.end();) {
        auto& socket = i->second;
        auto localPort = socket->port();
        if (socket->persistent()) {
            ++i;
            continue;
        }
        // Keep socket if there is a TCP socket using the same port.
        // Ignores listening TCP sockets as server should use persistent
        // port forwarding.
        auto tcp = std::ranges::find_if(tcpSockets, [&] (const SocketInfo& s) {
            if (std::ranges::binary_search(mySockets, s.inode))
                return false;
            if (s.localPort == localPort && s.state != TCP_LISTEN)
                return s.localAddr.isUnspecified() || s.localAddr == tunIP
                    || std::ranges::find(extraIPs, s.localAddr) != extraIPs.end();
            return false;
        });
        if (tcp != tcpSockets.end()) {
            ++i;
            continue;
        }
        // Keep socket if there is a corresponding UDP socket that is connected
        // to a SCION-mapped IP address or an unconnected socket that recently
        // had outgoing traffic.
        auto udp = std::ranges::find_if(udpSockets, [&] (const SocketInfo& s) {
            if (std::ranges::binary_search(mySockets, s.inode))
                return false;
            if (s.localPort != localPort)
                return false;
            if (s.remoteAddr.isScion()) {
                return s.localAddr.isUnspecified() || s.localAddr == tunIP
                    || std::ranges::find(extraIPs, s.localAddr) != extraIPs.end();
            } else if (s.remoteAddr.isUnspecified()) {
                return now - socket->lastUsed() < SOCKET_TIMEOUT;
            }
            return false;
        });
        if (udp != udpSockets.end()) {
            ++i;
            continue;
        }
        // Remove socket and all flows connected to it
        socket->close();
        i = sockets.erase(i);
        for (auto j = flows.begin(); j != flows.end(); ++j) {
            if (j->first.src.port() == localPort) {
                if (j->second->isMultipath()) {
                    j->second->lock().applyToSubflows([] (Flow& sf) {
                        sf.lock().close();
                    }).close();
                } else {
                    j->second->lock().close();
                }
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
                spdlog::critical("Signal handler error: {}\n", fmtError(ec));
                std::exit(EXIT_FAILURE);
            }
        }
        if (signal == SIGINT || signal == SIGTERM) {
            if (signal == SIGINT)
                spdlog::critical("Got SIGINT, stopping...");
            else
                spdlog::critical("Got SIGTERM, stopping...");
            stop();
            co_return;
        } else if (signal == SIGHUP) {
            // Reload configuration
            if (!policyFile.empty())
                reloadPathPolicy();
        } else if (signal == SIGUSR1) {
            printStatus(); // Print status to stdout
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
    co_return ErrorCode::Ok;
}

std::error_code ScitraTun::translateIPtoScion(TunQueue& tun)
{
    using std::uint8_t;
    using std::uint16_t;
    using L4Type = PacketBuffer::L4Type;
    PacketBuffer pkt{std::pmr::vector<std::byte>(PACKET_BUFFER_SIZE)};

    while (!shouldExit) {
        auto ec = tun.recvPacket(pkt); // blocking
        if (ec) {
            if (ec == ErrorCondition::Cancelled) {
                break;
            } else if (ec != ErrorCondition::InvalidPacket) {
                spdlog::error("IP->SCION Error reading from TUN queue: {}", fmtError(ec));
            }
            continue;
        }

        const auto recvd = std::chrono::steady_clock::now();

        generic::IPEndpoint localEp(pkt.ipv6.src, pkt.l4SPort());
        std::uint16_t remappedSPort = 0;
        bool mpOutOfPaths = false;
        std::shared_ptr<Flow> flow;
        auto [verdict, port, nextHop] = translateEgress(pkt, publicIP, REPLACE_ADDRESS,
            [&] (const ScIPAddress& src, const ScIPAddress& dst,
                uint16_t sport, uint16_t dport, hdr::ScionProto proto, uint8_t tc) {
            PathPtr path;
            std::uint16_t mtu = 0;
            ScIPAddress localAddr(localAS.isdAsn, src.host());
            FlowID flowid(localAddr, dst, sport, dport, proto);

            flow = getFlowEgress(pkt, flowid, localEp);
            remappedSPort = flowid.src.port();
            if (flow->isMultipath()) {
                flow = flow->getSubflowByAddr(localEp);
            }
            flow->lock().getPath(path);

            bool expiresSoon = false;
            auto now = std::chrono::utc_clock::now();
            if (path) {
                auto ttl = path->expiry() - now;
                if (flow->getType() == FlowType::Active)
                    expiresSoon = ttl < ACTIVE_FLOW_MIN_PATH_LIFE;
                else
                    expiresSoon = ttl < PASSIVE_FLOW_MIN_PATH_LIFE;
            }

            if (!path || path->broken() || expiresSoon) {
                // Test for MP_JOIN as well because isMultipath() updates too late.
                if (flow->isMultipath() || (pkt.l4Valid == L4Type::TCP && pkt.tcp.optMask.MpJoin)) {
                    if (!path) {
                        // Ensure that MPTCP subflows have unique paths.
                        // Looking for the lead flow here is the inverse operation to
                        // flow = flow->getSubflowByAddr(localEp). We could keep a pointer to the
                        // lead flow from earlier, but this code path is invoked only once per
                        // subflow so probably not worth it.
                        if (auto leadFlow = findFlow(flowid); leadFlow) {
                            auto lock = leadFlow->lock();
                            std::vector<PathPtr> paths;
                            lock.getAllPaths(paths);
                            path = selectPathMulti(flowid, tc, paths);
                            if (!path) {
                                mpOutOfPaths = true;
                                spdlog::debug("IP->SCION Not enough paths to establish subflow {}",
                                    flowid);
                                return std::make_pair(Maybe<PathPtr>(
                                    Error(ScitraError::NotEnoughPaths)), (std::uint16_t)0);
                            }
                        } else {
                            spdlog::debug("IP->SCION Can't find lead flow for {}", flowid);
                            return std::make_pair(Maybe<PathPtr>(
                                Error(ScitraError::NoLeadFlow)), (std::uint16_t)0);
                        }
                    } else {
                        // MPTCP subflows can't reselect their paths
                        path = refreshPath(path);
                        if (path->broken() || (path->expiry() - now).count() < 0) {
                            spdlog::debug("IP->SCION Path of MPTCP subflow {} is broken", flowid);
                            return std::make_pair(Maybe<PathPtr>(
                                Error(ScitraError::SubflowBroken)), (std::uint16_t)0);
                        }
                    }
                    spdlog::debug("Selected path for {} (subflow bound to {}): {}",
                        flowid, localEp, *path, mtu);
                } else {
                    path = selectPath(flowid, tc);
                    if (!path) return std::make_pair(
                        Maybe<PathPtr>(Error(ErrorCode::Pending)), (std::uint16_t)0);

                    spdlog::debug("Selected path for {}: {}", flowid, *path);
                }
                mtu = pmtu->getMtu(dst.host(), *path, recvd);
                spdlog::debug("Path {} has MTU of {} octets", *path, mtu);
            } else {
                mtu = pmtu->getMtu(dst.host(), *path, recvd);
            }
            flow->lock().setPath(path);
            return std::make_pair(Maybe<PathPtr>(std::move(path)), mtu);
        });

        if (verdict == Verdict::Pass) {
            // MPTCP: Remap source port
            if (remappedSPort && port != remappedSPort) {
                pkt.l4UpdateChecksum(remappedSPort, pkt.tcp.sport);
                pkt.tcp.sport = remappedSPort;
                port = remappedSPort;
            }
            if (auto socket = getSocket(port); socket) {
                assert(flow);
                flow->lock()
                    .updateStateEgress(pkt, recvd)
                    .countEgress(1, (std::uint32_t)pkt.payload().size());
                auto nh = generic::toUnderlay<asio::ip::udp::endpoint>(nextHop);
                if (!nh.has_value()) continue; // this should never happen
                auto ec = socket->sendPacket(pkt, *nh, recvd); // blocking
                if (ec) {
                    if (ec == std::errc::message_size) {
                        // MTU to next hop is lower than expected AS-internal MTU. Fall back to
                        // minimum safe MTU. The discovered MTU could be read from the socket's
                        // error queue, but it would be difficult to assign it to the right paths.
                        spdlog::warn("IP->SCION Translated packet too big to send to next hop '{}'."
                            " Falling back to minimum safe MTU. Consider setting --underlay-mtu",
                            " to a more conservative value.",
                            *nh);
                        pmtu->updateMtu(pkt.sci.dst.host(), pkt.path,
                            nextHop.host().is4() ? SAFE_MTU_IPV4 : SAFE_MTU_IPV6);
                    } else {
                        spdlog::error("IP->SCION Error sending packet to next hop '{}': {}",
                            *nh, fmtError(ec));
                    }
                }
            }
        } else if (verdict == Verdict::Return) {
            spdlog::debug("IP->SCION Return packet to local sender");
            auto ec = tun.sendPacket(pkt);
            if (ec) spdlog::error("IP->SCION Error sending packet to TUN: {}", fmtError(ec));
        } else if (mpOutOfPaths) {
            resetMptcpSubflow(flow, pkt, tun, recvd);
        } else {
            spdlog::debug("IP->SCION Packet dropped");
        }
        DBG_TIME_END(tun.lastRx, egrTicks, egrSamples);
    }
    return ScitraError::Cancelled;
}

// Reply to an MPTCP subflows SYN from localhost by resetting the subflow.
// Reset reason is given as lack of resources.
std::error_code ScitraTun::resetMptcpSubflow(
    const std::shared_ptr<Flow>& flow, PacketBuffer& pkt,
    TunQueue& tun, const std::chrono::steady_clock::time_point& recvd)
{
    using std::swap;

    swap(pkt.tcp.sport, pkt.tcp.dport);
    pkt.tcp.ack = pkt.tcp.seq + (std::uint32_t)pkt.payload().size() + 1; // ACK the SYN
    pkt.removePayload();
    pkt.tcp.flags = hdr::TCP::Flags::RST | hdr::TCP::Flags::ACK;
    pkt.tcp.seq = pkt.tcp.window = pkt.tcp.urgptr = 0;
    pkt.tcp.optMask = {};
    pkt.tcp.optMask.MpRst = 1;
    pkt.tcp.options.mpRst.flags = hdr::TcpMpRstOpt::Flags{};
    pkt.tcp.options.mpRst.reason = hdr::TcpMpRstOpt::Reason::LackOfResources;

    pkt.scionValid = false;
    swap(pkt.ipv6.src, pkt.ipv6.dst);
    pkt.ipv6.plen = (std::uint16_t)pkt.tcp.size();

    pkt.tcp.chksum = 0;
    pkt.tcp.chksum = hdr::details::internetChecksum(pkt.payload(),
        pkt.ipv6.checksum(pkt.ipv6.plen) + pkt.tcp.checksum());

    assert(flow);
    flow->lock().updateStateIngress(pkt, recvd);
    auto ec = tun.sendPacket(pkt);
    if (ec) spdlog::error("IP->SCION Error sending packet to TUN: {}", fmtError(ec));
    return ec;
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
            } else if (ec != ErrorCondition::StunReceived && ec != ErrorCondition::InvalidPacket) {
                spdlog::error("SCION->IP Error reading from socket: {}", fmtError(ec));
            }
            continue;
        }

        const auto recvd = std::chrono::steady_clock::now();

        // Packet Validation: Local socket port must match inner L4 header
        // destination port. If the inner L4 header does not contain a port, the
        // packet must have been received at the dispatcher port.
        if (pkt.l4DPort(DISPATCHER_PORT) != socket->port()) {
            spdlog::debug("SCION->IP Destination port validation failed");
            continue;
        }
        if (socket->port() == DISPATCHER_PORT && pkt.l4Valid != PacketBuffer::L4Type::SCMP) {
            spdlog::debug("SCION->IP Non-SCMP packet at dispatcher port");
            continue;
        }

        // Packet Validation: AS-internal traffic source must match source
        // host address in the SCION header.
        if (pkt.path.empty()) {
            auto src = generic::toGenericEp(from);
            if (pkt.sci.src.host() != src.host()) {
                spdlog::debug("SCION->IP AS-internal packet source address validation failed");
                continue;
            }
            if (pkt.l4SPort(DISPATCHER_PORT) != src.port()) {
                spdlog::debug("SCION->IP AS-internal packet source port validation failed");
                continue;
            }
        }

        // Handle SCMP
        if (pkt.l4Valid == PacketBuffer::L4Type::SCMP) {
            pathCache->handleScmp(pkt.sci.src, pkt.path, pkt.scmp.msg, pkt.payload());
        }

        // Check if the packet belongs to a known MPTCP subflow. If so,
        // find the local IP (assigned to the TUN interface) that is used
        // to identify the subflow in MPTCP.
        bool pathReversed = false;
        std::shared_ptr<Flow> flow;
        FlowID flowid(Igr, pkt);
        generic::IPEndpoint localEp(tunIP, pkt.l4DPort());
        if (!extraIPs.empty()) {
            if (flow = findFlow(FlowID(Igr, pkt)); flow) {
                if (flow->isMultipath()) {
                    if (auto ec = pkt.path.reverseInPlace(); ec) {
                        spdlog::debug("SCION->IP Reversing path failed");
                        continue;
                    }
                    pathReversed = true;
                    auto sf = flow->getSubflowByPath(pkt.path, extraIPs);
                    if (!sf) {
                        spdlog::debug("SCION->IP Can't accept subflow,"
                            " because we don't have enough addresses");
                        if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
                            if (pkt.tcp.flags[hdr::TCP::Flags::SYN]) {
                                rejectMptcpSubflow(flow, pkt, from, recvd);
                            }
                        }
                        continue;
                    }
                    flow = sf;
                    localEp = flow->getLocalEp();
                }
            }
        }

        // Attempt translation
        auto verdict = translateIngress(pkt, mappedIP, localEp.host(), 128,
            [&] (const hdr::SCION& sci, RawPath& rp)
            {
                if (!pathReversed) {
                    if (auto ec = rp.reverseInPlace(); ec) return (std::uint16_t)1280;
                    pathReversed = true;
                }
                return pmtu->getMtu(sci.src.host(), rp, std::chrono::steady_clock::now());
            }
        );
        if (verdict == Verdict::Pass) {
            if (!flow) flow = getFlowIngress(flowid, localEp);
            // Learn the connection token for additional subflows
            if (!extraIPs.empty() && pkt.l4Valid == PacketBuffer::L4Type::TCP) {
                if (pkt.tcp.optMask.MpCapable) {
                    auto& cap = pkt.tcp.options.mpCap;
                    if (cap.fieldMask.receiverKey) {
                        auto senderToken = scion::scitra::sha256_trunc(cap.senderKey);
                        spdlog::debug("MPTCP connection {} has receiver token {:08x} (key {})",
                            flowid, senderToken, cap.senderKey);
                        std::lock_guard lock(flowMutex);
                        mpTokenMap[senderToken] = flow;
                        flow->lock().setMptcpToken(senderToken);
                    }
                }
            }
            // Update flow state
            {
                auto proxy = flow->lock();
                proxy
                    .updateStateIngress(pkt, recvd)
                    .countIngress(1, (std::uint32_t)pkt.payload().size());
                if (bool updatePath = false; proxy.acceptsPassivePath(updatePath), updatePath) {
                    if (!pathReversed) {
                        if (auto ec = pkt.path.reverseInPlace(); ec)
                            spdlog::debug("SCION->IP Reversing path failed");
                        else
                            pathReversed = true;
                    }
                    if (pathReversed)
                        proxy.updatePassivePath(pkt.path, generic::toGenericEp(from));
                }
            }
            // MPTCP: Remap destination port
            if (pkt.l4Valid == PacketBuffer::L4Type::TCP && pkt.tcp.dport != localEp.port()) {
                auto dport = localEp.port();
                pkt.l4UpdateChecksum(dport, pkt.tcp.dport);
                pkt.tcp.dport = dport;
            }
            auto queue = flow->getQueue((std::uint32_t)tunQueues.size());
            auto ec = tunQueues[queue].sendPacket(pkt);
            if (ec) spdlog::error("SCION->IP Error sending packet to TUN (queue {}): {}",
                queue, fmtError(ec));
        } else {
            spdlog::debug("SCION->IP Packet dropped");
        }
        DBG_TIME_END(socket->lastRx, igrTicks, igrSamples);
    }
    co_return ScitraError::Cancelled;
}

// Reply to an MPTCP subflow SYN from a remote SCION host by resetting the
// subflow. Assumes that the path has already been reversed.
std::error_code ScitraTun::rejectMptcpSubflow(
    const std::shared_ptr<Flow>& flow, PacketBuffer& pkt,
    const boost::asio::ip::udp::endpoint& nh,
    const std::chrono::steady_clock::time_point& recvd)
{
    using std::swap;

    assert(flow);
    auto fl = flow->lock();
    fl.updateStateIngress(pkt, recvd);

    swap(pkt.tcp.sport, pkt.tcp.dport);
    pkt.tcp.ack = pkt.tcp.seq + (std::uint32_t)pkt.payload().size() + 1; // ACK the SYN
    pkt.removePayload();
    pkt.tcp.flags = hdr::TCP::Flags::RST | hdr::TCP::Flags::ACK;
    pkt.tcp.seq = pkt.tcp.window = pkt.tcp.urgptr = 0;
    pkt.tcp.optMask = {};
    pkt.tcp.optMask.MpRst = 1;
    pkt.tcp.options.mpRst.flags = hdr::TcpMpRstOpt::Flags{};
    pkt.tcp.options.mpRst.reason = hdr::TcpMpRstOpt::Reason::Prohibited;

    swap(pkt.sci.dst, pkt.sci.src);
    pkt.sci.plen = (std::uint16_t)pkt.tcp.size();

    pkt.tcp.chksum = 0;
    pkt.tcp.chksum = hdr::details::internetChecksum(pkt.payload(),
        pkt.sci.checksum(pkt.sci.plen, pkt.sci.nh) + pkt.tcp.checksum());

    fl.updateStateEgress(pkt, recvd);
    if (auto socket = getSocket(pkt.tcp.sport); socket) {
        auto ec = socket->sendPacket(pkt, nh, recvd); // blocking
        if (ec) {
            spdlog::error("IP->SCION Error sending packet to next hop '{}': {}", nh, fmtError(ec));
            return ec;
        }
    }
    return ErrorCode::Ok;
}

// Spawns a co-routine that queries paths to the given destination.
std::error_code ScitraTun::beginPathQuery(SharedPathCache& cache, IsdAsn src, IsdAsn dst)
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

// Returns possible paths for the given flow. May initiate an asynchronous path
// query if there are no cached paths.
Maybe<std::vector<PathPtr>> ScitraTun::getPathsForFlow(const FlowID& flowid, std::uint8_t tc)
{
    auto paths = pathCache->lookup(localAS.isdAsn, flowid.dst.isdAsn(),
        [this] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) {
            return beginPathQuery(cache, src, dst);
        }
    );

    if (paths) {
        if (auto policy = pathPolicy.load()) {
            auto filtered = policy->apply(flowid.src, flowid.dst, flowid.proto, tc, *paths);
            paths->resize(filtered.size());
        }
    }
    return paths;
}

// Find a newer version of the same path, i.e. a path with the same hop sequence
// but more up-to-date timestamps and MACs. May return `path` if no newer path
// is available.
PathPtr ScitraTun::refreshPath(const PathPtr& path)
{
    auto paths = pathCache->lookup(path->firstAS(), path->lastAS(),
        [this] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) {
            return beginPathQuery(cache, src, dst);
        }
    );

    if (paths) {
        for (const auto& candidate : *paths) {
            if (*candidate == *path) return candidate;
        }
    }
    return path;
}

// Select a new path from scratch. May return nullptr.
PathPtr ScitraTun::selectPath(const FlowID& flowid, std::uint8_t tc)
{
    auto paths = getPathsForFlow(flowid, tc);
    if (paths) {
        for (auto& path : *paths) {
            if (!path->broken()) return path;
        }
        return nullptr; // all paths have failed
    } else {
        if (paths.error() == ErrorCondition::Pending)
            return nullptr; // paths not ready yet
        else
            return nullptr; // no path
    }
}

// Select a new path that is not contained in `others`. Prefers paths that have
// the least overlap with the paths in `others`. May return nullptr.
PathPtr ScitraTun::selectPathMulti(
    const FlowID& flowid, std::uint8_t tc, const std::span<PathPtr>& others)
{
    auto paths = getPathsForFlow(flowid, tc);
    if (!paths) {
        if (paths.error() == ErrorCondition::Pending)
            return nullptr; // paths not ready yet
        else
            return nullptr; // no path
    }

    // Find path with the least overlap to other subflows
    float minOverlap = std::numeric_limits<float>::infinity();
    PathPtr best = nullptr;
    for (auto& path : *paths) {
        bool reject = false;
        float overlap = 0.0f;
        for (auto& other : others) {
            if (path->digest() == other->digest() && equalHops(*path, *other)) {
                reject = true; // path already in use by a different subflow
                break;
            } else {
                if (auto over = path->overlap(*other); over)
                    overlap += (float)over->first / (float)over->second;
                else
                    overlap += 1.0f; // assume full overlap if no other data is available
            }
        }
        if (!reject) {
            if (overlap == 0.0f) {
                return path;
            } else if (overlap < minOverlap) {
                minOverlap = overlap;
                best = path;
            }
        }
    }
    return best;
}

void ScitraTun::printStatus()
{
    const auto now = std::chrono::steady_clock::now();
    const auto date = std::chrono::system_clock::now();
    std::cout << std::format("### Scitra-TUN {:%F %T} ###\n", date);

    for (auto& flow : exportFlows(false)) {
        if (!flow.flags[FlowInfo::Flags::Multipath]) {
            auto proto = protoToString((int)flow.tuple.proto);
            std::cout << std::format(
                "{} -> {} [{}] bound_to {} type {} state {} time {:%M:%S}",
                flow.tuple.src,
                flow.tuple.dst,
                flow.boundTo,
                proto,
                toString(flow.type),
                toString(flow.state),
                now - flow.lastUsed
            );
        } else if (flow.tuple.proto == scion::hdr::ScionProto::TCP) {
            std::cout << std::format(
                "{} -> {} [{}] bound_to {} type {} state {} token {:08x} time {:%M:%S}",
                flow.tuple.src,
                flow.tuple.dst,
                flow.boundTo,
                "MPTCP",
                toString(flow.type),
                toString(flow.state),
                flow.mptcpRemoteToken,
                now - flow.lastUsed
            );
        }
        if (flow.path)
            std::cout << std::format(" path {} mtu {}", *flow.path, flow.mtu);
        std::cout << std::format(" tx_pkts {} tx_bytes {} rx_pkts {} rx_bytes {}",
            flow.counters.pktsEgress, flow.counters.bytesEgress,
            flow.counters.pktsIngress, flow.counters.bytesIngress);
        std::cout << '\n';
    }
    std::cout << std::flush;
}
