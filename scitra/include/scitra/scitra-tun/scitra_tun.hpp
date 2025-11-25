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
#include "scitra/translator.hpp"
#include "scitra/scitra-tun/cli_args.hpp"
#include "scitra/scitra-tun/flow.hpp"
#include "scitra/scitra-tun/netlink.hpp"
#include "scitra/scitra-tun/socket.hpp"
#include "scitra/scitra-tun/tun.hpp"

#include "scion/asio/addresses.hpp"
#include "scion/daemon/co_client.hpp"
#include "scion/path/policy.hpp"
#include "scion/path/shared_cache.hpp"
#include "scion/scmp/path_mtu.hpp"

#include <boost/asio.hpp>
#include <linux/if_ether.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace asio = boost::asio;
using namespace scion;
using namespace scion::scitra;


#ifndef NPERF_DEBUG
// Performance profiling and debugging data.
struct DbgPerformance
{
    std::uint32_t egrSamples;
    std::uint32_t igrSamples;
    std::uint64_t egrNanoSec;
    std::uint64_t igrNanoSec;
};
#endif // NPERF_DEBUG

struct FlowInfo
{
    FlowID tuple;
    FlowType type;
    FlowState state;
    std::uint8_t tc;
    FlowCounters counters;
    std::chrono::steady_clock::time_point lastUsed;
    scion::PathPtr path;
    std::uint16_t mtu;
};

class ScitraTun
{
private:
    // ASIO IO context for asynchronous file and socket operations. Is run an
    // all threads in `threads`. Decided against using boost::asio::thread_pool
    // as IO context, since I want to delay starting the threads until
    // initialization of the TUN queues and static sockets is completed.
    boost::asio::io_context ioCtx;
    // Worker threads that run IO completion handlers.
    std::vector<std::thread> threads;
    // Atomic flag that indicates when the application is in the teardown phase.
    std::atomic<bool> shouldExit = true;
    // Custom signal handling is implemented through ASIO.
    asio::signal_set signals;
    // Timer that starts bookkeeping tasks in regular intervals.
    boost::asio::steady_timer eventTimer;

    // ASIO IO context for gRPC. gRPC has it's own event loop, so a separate
    // context is needed.
    agrpc::GrpcContext grpcIoCtx;
    // Work guard that keeps grpcIoCtx running even when there are no RPCs in
    // progress.
    asio::executor_work_guard<typename agrpc::GrpcContext::executor_type> grpcWorkGuard;
    // gRPC connection to SCION daemon.
    scion::daemon::CoGrpcDaemonClient daemon;
    // Local AS information.
    scion::daemon::AsInfo localAS;
    // Whether to accept SCMP packets at the dispatcher port.
    const bool enableScmpDispatch;
    // Ports whose underlay sockets are always open.
    const std::vector<std::uint16_t> staticPorts;
    // Configured number of queues in the TUN interface.
    const std::uint32_t configQueues;
    // Configured number of worker threads.
    const std::uint32_t configThreads;

    // Public underlay IP address used by SCION. Can be an IPv4 or IPv6 address.
    scion::generic::IPAddress publicIP;
    // SCION-mapped publicIP.
    scion::generic::IPAddress mappedIP;
    // IPv6 address of the TUN interface. May be equal to mappedIP.
    scion::generic::IPAddress tunIP;
    // Name of the network interface used for SCION communication.
    std::string netDevice;
    // Name of the TUN interface.
    std::string tunDevice;

    // Queues of the TUN interface
    std::vector<TunQueue> tunQueues;

    // Mutex that must be held when accessing `sockets`
    mutable std::shared_mutex socketMutex;
    // UDP sockets for communication with border routers and other SCION hosts.
    // Indexed by local port.
    std::map<std::uint16_t, std::shared_ptr<Socket>> sockets;

    // Mutex that must be held when accessing `flows`.
    mutable std::mutex flowMutex;
    // Active flows/connections using the translator. Indexed by flow ID.
    std::unordered_map<FlowID, std::shared_ptr<Flow>> flows;

    std::filesystem::path policyFile;
    std::atomic<std::shared_ptr<path_policy::PolicySet>> pathPolicy;
    std::unique_ptr<scion::SharedPathCache> pathCache;
    std::unique_ptr<scion::PathMtuDiscoverer<>> pmtu;

    // Debug
#ifndef NPERF_DEBUG
    mutable std::atomic<std::uint32_t> egrSamples;
    mutable std::atomic<std::uint32_t> igrSamples;
    mutable std::atomic<std::uint64_t> egrTicks;
    mutable std::atomic<std::uint64_t> igrTicks;
#endif // NPERF_DEBUG

public:
    ScitraTun(const Arguments& args);
    ScitraTun(const ScitraTun&) = delete;
    ScitraTun(ScitraTun&&) = delete;
    ScitraTun operator=(const ScitraTun&) = delete;
    ScitraTun operator=(ScitraTun&&) = delete;
    ~ScitraTun();

    /// \brief Start the worker threads.
    void run();

    /// \brief Signal all threads to stop.
    void stop();

    /// \brief Poll whether the translator is still running.
    bool running() const { return !shouldExit; }

    /// \brief Block and join with worker threads when done.
    void join();

    ScIPAddress getHostAddress() const
    {
        return ScIPAddress(localAS.isdAsn, publicIP);
    }

    generic::IPAddress getMappedAddress() const { return mappedIP; }
    generic::IPAddress getTunAddress() const { return tunIP; }
    std::string_view getPublicIfaceName() const { return netDevice; }
    std::string_view getTunName() const { return tunDevice; }

    /// \brief Start refreshing paths to `dst` now. Returns immediately without
    /// blocking.
    void refreshPaths(IsdAsn dst);

    /// \brief Returns all paths available to a flow taking the path policy into
    /// account. If the requests flow does not exist, returns an empty list.
    std::vector<PathPtr> getPaths(const FlowID& flowid, std::uint8_t tc) const;

    /// \brief Override the path selection the specified flow. Has no effect on
    /// passive flows where the remote hosts selects the paths.
    void overrideFlowPath(const FlowID& flowid, PathPtr path);

    /// \brief Remove a flow immediately.
    void removeFlow(const FlowID& flowid);

#ifndef NPERF_DEBUG
    DbgPerformance getDebugInfo() const
    {
        return {
            egrSamples.exchange(0),
            igrSamples.exchange(0),
            egrTicks.exchange(0),
            igrTicks.exchange(0),
        };
    }
#endif // NPERF_DEBUG

    std::vector<FlowInfo> exportFlows(bool resetCounters) const;

    /// \brief Load a path policy.
    std::error_code loadPathPolicy(const std::filesystem::path& path);

    /// \brief Reload the most recently loaded policy file.
    std::error_code reloadPathPolicy();

private:
    Maybe<std::shared_ptr<Socket>> openSocket(std::uint16_t port, bool persistent);
    std::shared_ptr<Socket> getSocket(std::uint16_t port);
    void closeSocket(std::uint16_t port);
    void maintainFlowsAndSockets();

    asio::awaitable<void> signalHandler();
    asio::awaitable<std::error_code> tick();
    asio::awaitable<std::error_code> translateIPtoScion(TunQueue& tun);
    asio::awaitable<std::error_code> translateScionToIP(std::shared_ptr<Socket> socket);

    std::shared_ptr<Flow> getFlow(const FlowID& id, FlowType type);
    std::error_code queryPaths(SharedPathCache& cache, IsdAsn src, IsdAsn dst);
    Maybe<PathPtr> selectPath(
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc);
    void printStatus();
};
