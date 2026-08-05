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

#include "scion/addr/address.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/path/path.hpp"
#include "scitra/packet.hpp"
#include "scitra/scitra-tun/error_codes.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <random>


enum class FlowType
{
    Active,  // Flow was initiated by this host
    Passive, // Flow was initiated by a remote host
};

enum class FlowState
{
    CLOSED,      // no more packets expected
    CLOSED_WAIT, // waiting for subflows to close
    // values > CLOSED_WAIT indicate a closed connection
    OPEN,        // UDP send/received
    SYN_SENT,    // TCP SCN sent
    SYN_RCVD,    // TCP SYN received
    ESTABLISHED, // TCP established
    // values > ESTABLISHED indicate that the connection is being torn down
    FIN,         // TCP FIN send/received
    RST,         // TCP RST send/received
    TIMEOUT,     // flow timeout
};

inline const char* protoToString(int proto)
{
    using namespace scion::hdr;
    switch (proto) {
    case (int)IPProto::ICMP:
        return "ICMP";
    case (int)IPProto::TCP:
        return "TCP";
    case (int)IPProto::UDP:
        return "UDP";
    case (int)IPProto::ICMPv6:
        return "ICMPv6";
    case (int)ScionProto::SCMP:
        return "SCMP";
    default:
        return "error";
    }
}

inline const char* toString(FlowType type)
{
    switch (type) {
    case FlowType::Active:
        return "active";
    case FlowType::Passive:
        return "passive";
    default:
        return "error";
    }
}

inline const char* toString(FlowState state)
{
    switch (state) {
    case FlowState::CLOSED:
        return "CLOSED";
    case FlowState::CLOSED_WAIT:
        return "CLOSED_WAIT";
    case FlowState::OPEN:
        return "OPEN";
    case FlowState::SYN_SENT:
        return "SYN_SENT";
    case FlowState::SYN_RCVD:
        return "SYN_RCVD";
    case FlowState::ESTABLISHED:
        return "ESTABLISHED";
    case FlowState::FIN:
        return "FIN";
    case FlowState::RST:
        return "RST";
    case FlowState::TIMEOUT:
        return "TIMEOUT";
    default:
        return "error";
    }
}

struct FlowCounters
{
    std::uint32_t pktsEgress;
    std::uint32_t bytesEgress;
    std::uint32_t pktsIngress;
    std::uint32_t bytesIngress;
};

enum EgrTag { Egr };
enum IgrTag { Igr };

struct FlowID
{
    scion::ScIPEndpoint src;
    scion::ScIPEndpoint dst;
    scion::hdr::ScionProto proto = scion::hdr::ScionProto::TCP;

    FlowID() = default;
    FlowID(const scion::ScIPAddress& src, const scion::ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, scion::hdr::ScionProto proto)
        : src(src, sport)
        , dst(dst, dport)
        , proto(mapProto((int)proto))
    {}
    FlowID(EgrTag, const scion::scitra::PacketBuffer& pkt)
        : src(pkt.sci.src, pkt.l4SPort())
        , dst(pkt.sci.dst, pkt.l4DPort())
        , proto(mapProto((int)pkt.l4Valid))
    {}
    FlowID(IgrTag, const scion::scitra::PacketBuffer& pkt)
        : src(pkt.sci.dst, pkt.l4DPort())
        , dst(pkt.sci.src, pkt.l4SPort())
        , proto(mapProto((int)pkt.l4Valid))
    {}

    bool operator==(const FlowID&) const = default;

private:
    static scion::hdr::ScionProto mapProto(int proto)
    {
        // Throw SCMP and ICMPv6 into the same bucket as we freely translate
        // between them.
        if (proto == (int)scion::hdr::IPProto::ICMPv6)
            return scion::hdr::ScionProto::SCMP;
        return scion::hdr::ScionProto(proto);
    }
};

template <>
struct std::formatter<FlowID>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const FlowID& id, auto& ctx) const
    {
        return std::format_to(ctx.out(), "{} -> {} ({})",
            id.src, id.dst, protoToString((int)id.proto));
    }
};

template <>
struct std::hash<FlowID>
{
    std::size_t operator()(const FlowID& addr) const noexcept
    {
        std::hash<scion::ScIPEndpoint> h1;
        return h1(addr.src) ^ h1(addr.dst) ^ (std::size_t)addr.proto;
    }
};

class FlowProxy;

/// \internal \brief State of a packet flow through the translator.
///
/// ### Multipath Support ###
/// Multipath (i.e. MPTCP) connections consist of multiple subflows. Each
/// subflow is represented by its own instance of Flow. Scitra-TUN manipulates
/// flows so that all subflows of the same connection share the same 5-tuple but
/// have different SCION paths.
///
/// The first subflow that hits the translator is considered the **lead flow**.
/// This may or may not be the first subflow that has been established depending
/// on when Scitra-TUN has been started and whether there are subflows that do
/// not pass through Scitra-TUN. Additional subflows are stored in the
/// `subflows` vector of the lead flow, so that all subflows are stored
/// together. Non-lead flows should have an empty `subflows` vector.
///
/// The lead flow my be in a closed state while other subflows still exist. In
/// this case the lead flow should must not be deleted yet.
class Flow : public std::enable_shared_from_this<Flow>
{
private:
    const scion::generic::IPEndpoint boundTo;
    const FlowType type;
    const std::uint32_t queue;
    std::atomic<bool> multipath = false;

    FlowState state = FlowState::OPEN;
    FlowCounters counters = {};
    scion::PathPtr path;
    std::uint8_t tc = 0;
    std::uint32_t mptcpToken = 0;
    std::chrono::steady_clock::time_point lastUsed;

    std::mutex mutex;
    std::vector<std::shared_ptr<Flow>> subflows;

    friend class FlowProxy;

public:
    static inline const auto FLOW_TIMEOUT = std::chrono::seconds(120);

    Flow(const scion::generic::IPEndpoint& boundTo, FlowType type,
        std::uint32_t queue, bool multipath)
        : boundTo(boundTo), type(type), queue(queue), multipath(multipath)
    {}

    /// \internal \brief Create a new flow or subflow.
    /// \param boundTo Local IP endpoint fo the flow. Different subflows of
    /// the same multipath flow must have different local IP endpoints.
    /// \param type Flow type. Active or Passive.
    /// \param multipath Initial state of the multipath flag.
    static std::shared_ptr<Flow> Create(
        const scion::generic::IPEndpoint& boundTo, FlowType type)
    {
        return std::make_shared<Flow>(boundTo, type, randomQueueId(), false);
    }

    static std::shared_ptr<Flow> CreateSubflow(
        const scion::generic::IPEndpoint& boundTo, FlowType type, std::uint32_t token)
    {
        auto flow = std::make_shared<Flow>(boundTo, type, randomQueueId(), true);
        flow->mptcpToken = token;
        return flow;
    }

    FlowType getType() const { return type; }

    std::uint32_t getQueue(std::uint32_t queues) const
    {
        return queue % queues;
    }

    /// \brief Returns the local IP address and port before translation.
    const scion::generic::IPEndpoint& getLocalEp() const
    {
        return boundTo;
    }

    bool isMultipath() const
    {
        return multipath.load();
    }

    /// \internal \brief Find or create a subflow by looking for a matching
    /// local IP end point. If this flow is not the lead flow of a multipath
    /// connection, this method will always return a pointer to the flow it has
    /// been called on.
    /// \note For multipath connections, this should be called on the lead flow
    /// of the connection.
    /// \param localEp IP address and port of the local end point. Used for
    /// differentiating between different subflows in multipath transport
    /// protocols.
    std::shared_ptr<Flow> getSubflowByAddr(const scion::generic::IPEndpoint& localEp)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto sf = findSubflowByAddr(localEp);
        if (sf) return sf;
        spdlog::debug("New {} subflow locally bound to {}", toString(type), localEp);
        sf = CreateSubflow(localEp, FlowType::Active, mptcpToken);
        subflows.push_back(sf);
        return sf;
    }

    /// \internal \brief Find or create a subflow using the given path.
    /// \note For multipath connections, this should be called on the lead flow
    /// of the connection.
    /// \param path Subflow path to search for.
    /// \param addrPool Set of IP addresses to choose from if a new subflow is
    /// created. If all addresses in the pool are already in use, no subflow
    /// is created and the function returns nullptr.
    std::shared_ptr<Flow> getSubflowByPath(
        const scion::RawPath& path,
        std::span<const scion::generic::IPAddress> addrPool)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto sf = findSubflowByPath(path);
        if (sf) return sf;

        for (auto& addr : addrPool) {
            auto i = std::ranges::find_if(subflows, [&] (const auto& sf) {
                return sf->boundTo.host() == addr;
            });
            if (i == subflows.end()) {
                scion::generic::IPEndpoint ep(addr, boundTo.port());
                spdlog::debug("New {} subflow locally bound to {}", toString(type), ep);
                sf = CreateSubflow(ep, FlowType::Passive, mptcpToken);
                subflows.push_back(sf);
                return sf;
            }
        }
        return nullptr; // error: all addresses in use
    }

    // Acquire a lock on the flow.
    FlowProxy lock();

private:
    static std::uint32_t randomQueueId()
    {
        static std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<std::uint32_t> dist;
        return dist(rng);
    }

    std::shared_ptr<Flow> findSubflowByAddr(const scion::generic::IPEndpoint& addr)
    {
        if (!multipath.load()) {
            return shared_from_this();
        } else {
            if (boundTo == addr) return shared_from_this();
            auto i = std::ranges::find_if(subflows, [&] (const auto& sf) {
                return sf->boundTo == addr;
            });
            if (i != subflows.end()) {
                return *i;
            }
        }
        return nullptr;
    }

    std::shared_ptr<Flow> findSubflowByPath(const scion::RawPath& path)
    {
        if (!multipath.load()) {
            return shared_from_this();
        } else {
            if (this->path->digest() == path.digest() && equalHops(*this->path, path))
                return shared_from_this();
            auto i = std::ranges::find_if(subflows, [&] (const auto& sf) {
                if (!sf->path) return false;
                return sf->path->digest() == path.digest() && equalHops(*sf->path, path);
            });
            if (i != subflows.end()) {
                return *i;
            }
        }
        return nullptr;
    }
};

class FlowProxy
{
private:
    Flow& flow;
    std::lock_guard<std::mutex> lock;

    explicit FlowProxy(Flow& flow)
        : flow(flow), lock(flow.mutex)
    {}

    friend class Flow;

public:
    // Apply void f(Flow&) to all subflows, but not this flow itself.
    template <typename F>
    FlowProxy& applyToSubflows(F f)
    {
        for (auto& sf : flow.subflows) f(*sf);
        return *this;
    }

    // Apply bool f(Flow&) to all subflows, but not this flow itself.
    // If f returns true, the subflows is removed.
    template <typename F>
    FlowProxy& removeSubflows(F f)
    {
        for (auto i = flow.subflows.begin(); i != flow.subflows.end();) {
            if (f(**i)) i = flow.subflows.erase(i);
            else ++i;
        }
        return *this;
    }

    FlowProxy& getMptcpToken(std::uint32_t& token)
    {
        token = flow.mptcpToken;
        return *this;
    }

    FlowProxy& setMptcpToken(std::uint32_t token)
    {
        flow.mptcpToken = token;
        return *this;
    }

    // Writes pointers to the paths of this flow and all its subflows to
    // paths. The previous contents of paths are overwritten. Takes temporary
    // locks on the subflows.
    FlowProxy& getAllPaths(std::vector<scion::PathPtr>& paths)
    {
        paths.resize(0);
        paths.reserve(flow.subflows.size() + 1);
        if (flow.path) paths.push_back(flow.path);
        for (auto& sf : flow.subflows) {
            scion::PathPtr path;
            sf->lock().getPath(path);
            if (path) paths.push_back(path);
        }
        return *this;
    }

    // Get the path currently assigned to the flow.
    FlowProxy& getPath(scion::PathPtr& path)
    {
        path = flow.path;
        return *this;
    }

    // Unconditionally assigns a new path to the flow.
    FlowProxy& setPath(scion::PathPtr path)
    {
        flow.path = std::move(path);
        return *this;
    }

    // Returns whether updatePassivePath() can accept a new path or not.
    FlowProxy& acceptsPassivePath(bool& acceptsPath)
    {
        acceptsPath = flow.type == FlowType::Passive && (!flow.multipath || !flow.path);
        return *this;
    }

    // Replace the flow's current path with the given raw path if the flow is
    // passive and the new path is different from the current one or if the new
    // path's expiry is further in the future.
    // For multipath flows, this function sets the initial path, but does not
    // allow updating the path afterwards.
    FlowProxy& updatePassivePath(const scion::RawPath& rp, const scion::generic::IPEndpoint& nh)
    {
        if (flow.type == FlowType::Passive && (!flow.multipath || !flow.path)) {
            if (flow.path) {
                if (flow.path->digest() != rp.digest() || flow.path->expiry() < rp.expiry()) {
                    flow.path = scion::makePath(rp, nh);
                }
            } else {
                flow.path = scion::makePath(rp, nh);
            }
        }
        return *this;
    }

    // Returns the current flow state in `state`.
    FlowProxy& getState(FlowState& state)
    {
        state = flow.state;
        return *this;
    }

    // Returns the traffic class of the last packet in `tc`.
    FlowProxy& getTrafficClass(std::uint8_t& tc)
    {
        tc = flow.tc;
        return *this;
    }

    // Returns the last time the flow state was updated in `t`.
    FlowProxy& getLastUpdate(std::chrono::steady_clock::time_point& t)
    {
        t = flow.lastUsed;
        return *this;
    }

    // Set the flow state to closed.
    FlowProxy& close()
    {
        flow.state = FlowState::CLOSED;
        return *this;
    }

    // Advances the flow state.
    FlowProxy& tick(const std::chrono::steady_clock::time_point& now)
    {
        if ((int)flow.state > (int)FlowState::ESTABLISHED) {
            if (flow.isMultipath())
                flow.state = FlowState::CLOSED_WAIT;
            else
                flow.state = FlowState::CLOSED;
        } else if (flow.state != FlowState::CLOSED
                && flow.state != FlowState::ESTABLISHED) {
            if (now - flow.lastUsed > Flow::FLOW_TIMEOUT)
                flow.state = FlowState::TIMEOUT;
        }
        if (flow.state == FlowState::CLOSED_WAIT && flow.subflows.empty()) {
            flow.state = FlowState::CLOSED;
        }
        return *this;
    }

    // Log the last outgoing packet at time `t` and update the flow state.
    FlowProxy& updateStateEgress(
        const scion::scitra::PacketBuffer& pkt,
        const std::chrono::steady_clock::time_point& t)
    {
        using namespace scion::scitra;
        using scion::hdr::TCP;
        if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
            // Guess TCP connection state
            if (pkt.tcp.flags & (TCP::Flags::FIN | TCP::Flags::RST)) {
                if (pkt.tcp.flags & TCP::Flags::FIN)
                    flow.state = FlowState::FIN;
                else
                    flow.state = FlowState::RST;
            } else {
                if (flow.state == FlowState::SYN_RCVD) {
                    if (pkt.tcp.flags & TCP::Flags::ACK) {
                        flow.state = FlowState::ESTABLISHED;
                        if (pkt.tcp.optMask.MpCapable) flow.multipath.store(true);
                    }
                } else {
                    if (pkt.tcp.flags & TCP::Flags::SYN) {
                        flow.state = FlowState::SYN_SENT;
                        if (pkt.tcp.optMask.MpJoin) flow.multipath.store(true);
                    } else if (flow.state != FlowState::FIN && flow.state != FlowState::RST) {
                        flow.state = FlowState::ESTABLISHED;
                        if (pkt.tcp.optMask.MpCapable
                            | pkt.tcp.optMask.MpDss
                            | pkt.tcp.optMask.MpAddAddr
                            | pkt.tcp.optMask.MpRemAddr
                            | pkt.tcp.optMask.MpPrio) {
                            flow.multipath.store(true);
                        }
                    }
                }
            }
        } else {
            // UDP or ICMP/SCMP
            flow.state = FlowState::OPEN;
        }
        assert(pkt.scionValid); // egress packet must be SCION
        flow.tc = pkt.sci.qos >> 2;
        flow.lastUsed = t;
        return *this;
    }

    // Log the last incoming packet at time `t` and update the flow state.
    FlowProxy& updateStateIngress(
        const scion::scitra::PacketBuffer& pkt,
        const std::chrono::steady_clock::time_point& t)
    {
        using namespace scion::scitra;
        using scion::hdr::TCP;
        if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
            // Guess TCP connection state
            if (pkt.tcp.flags & (TCP::Flags::FIN | TCP::Flags::RST)) {
                if (pkt.tcp.flags & TCP::Flags::FIN)
                    flow.state = FlowState::FIN;
                else
                    flow.state = FlowState::RST;
            } else {
                if (flow.state == FlowState::SYN_SENT) {
                    if (pkt.tcp.flags[TCP::Flags::SYN] && pkt.tcp.flags[TCP::Flags::ACK]) {
                        flow.state = FlowState::ESTABLISHED;
                        if (pkt.tcp.optMask.MpCapable) flow.multipath.store(true);
                    }
                } else {
                    if (pkt.tcp.flags & TCP::Flags::SYN) {
                        flow.state = FlowState::SYN_RCVD;
                        if (pkt.tcp.optMask.MpJoin) flow.multipath.store(true);
                    } else if (flow.state != FlowState::FIN && flow.state != FlowState::RST) {
                        flow.state = FlowState::ESTABLISHED;
                        if (pkt.tcp.optMask.MpCapable
                            | pkt.tcp.optMask.MpDss
                            | pkt.tcp.optMask.MpAddAddr
                            | pkt.tcp.optMask.MpRemAddr
                            | pkt.tcp.optMask.MpPrio) {
                            flow.multipath.store(true);
                        }
                    }
                }
            }
        } else {
            // UDP or ICMP/SCMP
            flow.state = FlowState::OPEN;
        }
        flow.lastUsed = t;
        return *this;
    }

    FlowProxy& countEgress(std::uint32_t pkts, std::uint32_t bytes)
    {
        flow.counters.pktsEgress += pkts;
        flow.counters.bytesEgress += bytes;
        return *this;
    }

    FlowProxy& countIngress(std::uint32_t pkts, std::uint32_t bytes)
    {
        flow.counters.pktsIngress += pkts;
        flow.counters.bytesIngress += bytes;
        return *this;
    }

    FlowProxy& getCounters(FlowCounters& counters)
    {
        counters = flow.counters;
        return *this;
    }

    FlowProxy& resetCounters()
    {
        flow.counters = {};
        return *this;
    }
};

inline FlowProxy Flow::lock()
{
    return FlowProxy(*this);
}
