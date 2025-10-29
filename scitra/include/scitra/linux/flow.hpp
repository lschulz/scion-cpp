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

#include "scitra/linux/error_codes.hpp"
#include "scitra/packet.hpp"
#include "scion/addr/address.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/path/path.hpp"

#include <cstdint>
#include <mutex>


enum class FlowType
{
    Active, // Flow was initiated by this host
    Passive // Flow was initiated by a remote host
};

enum class FlowState
{
    CLOSED,      // no more packets expected
    OPEN,        // UDP send/received
    SYN,         // TCP SYN sent or received
    ESTABLISHED, // TCP w/o SYN, FIN, or RST
    CLOSING,     // TCP FIN or RST send/received
};

struct FlowCounters
{
    std::uint32_t pktsIngress;
    std::uint32_t bytesIngress;
    std::uint32_t pktsEgress;
    std::uint32_t bytesEgress;
};

enum EgrTag { Egr };
enum IgrTag { Igr };

struct FlowID
{
    scion::ScIPEndpoint src;
    scion::ScIPEndpoint dst;
    scion::hdr::ScionProto proto = scion::hdr::ScionProto::SCMP;

    FlowID() = default;
    FlowID(const scion::ScIPAddress& src, const scion::ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, scion::hdr::ScionProto proto)
        : src(src, sport)
        , dst(dst, dport)
        , proto(proto)
    {}
    FlowID(EgrTag, const scion::scitra::PacketBuffer& pkt)
        : src(pkt.sci.src, pkt.l4SPort())
        , dst(pkt.sci.dst, pkt.l4DPort())
        , proto(static_cast<scion::hdr::ScionProto>(pkt.l4Valid))
    {}
    FlowID(IgrTag, const scion::scitra::PacketBuffer& pkt)
        : src(pkt.sci.dst, pkt.l4DPort())
        , dst(pkt.sci.src, pkt.l4SPort())
        , proto(static_cast<scion::hdr::ScionProto>(pkt.l4Valid))
    {}

    bool operator==(const FlowID&) const = default;
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

class Flow
{
private:
    const FlowType type;
    std::mutex mutex;
    FlowState state = FlowState::OPEN;
    FlowCounters counters = {};
    scion::PathPtr path;

    friend class FlowProxy;

public:
    explicit Flow(FlowType type)
        : type(type)
    {}

    FlowType getType() const { return type; }

    // Acquire a lock on the path.
    FlowProxy lock();
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

    // Replace the flow's current path with the given raw path if the flow is
    // passive and the new path is different from the current one or if the new
    // path'S expiry is further in the future.
    FlowProxy& updatePassivePath(const scion::RawPath& rp, const scion::generic::IPEndpoint& nh)
    {
        if (flow.type == FlowType::Passive) {
            if (flow.path) {
                if (flow.path->digest() != rp.digest() && flow.path->expiry() < rp.expiry()) {
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

    // Set the flow state to closed.
    FlowProxy& close()
    {
        flow.state = FlowState::CLOSED;
        return *this;
    }

    // Advances the flow state by one tick.
    FlowProxy& tick()
    {
        if (flow.state == FlowState::CLOSING)
            flow.state = FlowState::CLOSED;
        return *this;
    }

    // Update the flow state by analyzing the headers of the last observed
    // packet.
    FlowProxy& updateState(const scion::scitra::PacketBuffer& pkt)
    {
        using namespace scion::scitra;
        using scion::hdr::TCP;
        if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
            if (pkt.tcp.flags & TCP::Flags::SYN) {
                flow.state = FlowState::SYN;
            } else if (pkt.tcp.flags & (TCP::Flags::FIN | TCP::Flags::RST)) {
                flow.state = FlowState::CLOSING;
            } else if (flow.state == FlowState::SYN) {
                flow.state = FlowState::ESTABLISHED;
            }
        } else {
            flow.state = FlowState::OPEN;
        }
        return *this;
    }

    FlowProxy& countIngress(std::uint32_t pkts, std::uint32_t bytes)
    {
        flow.counters.pktsIngress += pkts;
        flow.counters.bytesIngress += bytes;
        return *this;
    }

    FlowProxy& countEgress(std::uint32_t pkts, std::uint32_t bytes)
    {
        flow.counters.pktsEgress += pkts;
        flow.counters.bytesEgress += bytes;
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
