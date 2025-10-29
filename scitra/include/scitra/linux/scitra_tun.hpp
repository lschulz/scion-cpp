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

#include "scitra/linux/cli_args.hpp"
#include "scitra/linux/flow.hpp"
#include "scitra/linux/netlink.hpp"
#include "scitra/linux/socket.hpp"
#include "scitra/linux/tun.hpp"
#include "scitra/packet.hpp"
#include "scitra/translator.hpp"

#include "scion/asio/addresses.hpp"
#include "scion/daemon/co_client.hpp"
#include "scion/path/policy.hpp"
#include "scion/path/shared_cache.hpp"
#include "scion/scmp/path_mtu.hpp"

#include <boost/asio.hpp>
#include <linux/if_ether.h>

#include <atomic>
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
    std::atomic<bool> shouldExit = false;
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
    // Ports that bypass the dispatcher in the local AS.
    scion::daemon::PortRange dispPorts;

    // Public IP address used by SCION.
    scion::generic::IPAddress publicIP;
    // IPv6 address of the TUN interface. Generated from publicIP.
    scion::generic::IPAddress tunIP;
    // Name of the network interface used for SCION communication.
    std::string netDevice;
    // Name of the TUN interface.
    std::string tunDevice;
    // Don't bind sockets to netDevice.
    bool noDeviceBind;

    // Queues of the TUN interface
    std::vector<TunQueue> tunQueues;

    // Mutex that must be held when accessing `sockets`
    std::shared_mutex socketMutex;
    // UDP sockets for communication with border routers and other SCION hosts.
    // Indexed by local port.
    std::map<std::uint16_t, std::shared_ptr<Socket>> sockets;

    // Mutex that must be held when accessing `flows`.
    std::mutex flowMutex;
    // Active flows/connections using the translator. Indexed by flow ID.
    std::unordered_map<FlowID, std::shared_ptr<Flow>> flows;

    std::unique_ptr<path_policy::PolicySet> pathPolicy;
    std::unique_ptr<scion::SharedPathCache> pathCache;
    std::unique_ptr<scion::PathMtuDiscoverer<>> pmtu;

public:
    ScitraTun(const Arguments& args);
    ScitraTun(const ScitraTun&) = delete;
    ScitraTun(ScitraTun&&) = delete;
    ScitraTun operator=(const ScitraTun&) = delete;
    ScitraTun operator=(ScitraTun&&) = delete;
    ~ScitraTun();

    /// \brief Start the worker threads.
    void run(const Arguments& args);

    /// \brief Signal all threads to stop.
    void stop();

    /// \brief Block and join with worker threads when done.
    void join();

private:
    Maybe<std::shared_ptr<Socket>> openSocket(std::uint16_t port, bool permanent);
    std::shared_ptr<Socket> getSocket(std::uint16_t port);
    void closeSocket(std::uint16_t port);
    void maintainFlowsAndSockets();

    asio::awaitable<void> signalHandler();
    asio::awaitable<std::error_code> tick();
    asio::awaitable<std::error_code> translateIPtoScion(TunQueue& tun);
    asio::awaitable<std::error_code> translateScionToIP(std::shared_ptr<Socket> socket);

    // Get an existing flow or create a new one. If a new flow is created
    // it will be of type `type`, otherwise `type` is ignored.
    std::shared_ptr<Flow> getFlow(const FlowID& id, FlowType type)
    {
        std::lock_guard lock(flowMutex);
        auto flow = flows[id];
        if (!flow) {
            flow = std::make_shared<Flow>(type);
            flows[id] = flow;
        }
        return flow;
    }

    std::error_code queryPaths(SharedPathCache& cache, IsdAsn src, IsdAsn dst);
    Maybe<PathPtr> selectPath(
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc);
};
