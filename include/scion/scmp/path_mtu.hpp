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
#include "scion/addr/isd_asn.hpp"
#include "scion/details/debug.hpp"
#include "scion/path/path.hpp"
#include "scion/scmp/handler.hpp"

#include <memory>
#include <unordered_map>


namespace scion {

/// \brief PathMtuDiscoverer stores the Path MTUs (PMTU) for a set of
/// destinations and SCION paths. It is intended to support implementations of
/// RFC1981-style Path MTU discovery for SCION. The Path MTUs are initially
/// taken from the control place supplied values. If an SCMP message indicating
/// a packet that a packet was too big is received, the Path MTU is updated.
///
/// \details In order to use the class it must be registered as SCMP handler in
/// all sockets for which the Path MTU should be stored. Before sending a
/// packet, the latest known PMTU can be retrieved with getMtu(). In order to
/// calculate the maximum payload size, the size of the SCION header, path,
/// extension headers, and L4 headers must be subtracted from the PMTU.
///
/// Example:
///     UdpSocket s;
///     PathMtuDiscoverer pmtu;
///     s.setNextScmpHandler(&pmtu);
///     size_t mtu = pmtu.getMtu(dest, path);
///     size_t hdrSize = s.measure(path).value();
///     size_t maxPayloadSize = mtu > hdrSize ? mtu - hdrSize : 0;
///
/// Stream-oriented sockets keep track of the Path MTU internally and usually
/// don't need this class.
template <typename Alloc = std::allocator<std::byte>>
class PathMtuDiscoverer : public ScmpHandlerImpl
{
private:
    struct Destination
    {
        ScIPAddress address;
        PathDigest path;
        bool operator==(const Destination& other) const = default;
    };

    struct HashDest
    {
        std::size_t operator()(const Destination& dest) const noexcept
        {
            return std::hash<ScIPAddress>{}(dest.address) ^ std::hash<PathDigest>{}(dest.path);
        }
    };

    struct MtuRecord
    {
        std::uint16_t mtu;
    };

    std::uint16_t m_maximumMtu;
    using MapAlloc = typename std::allocator_traits<Alloc>::template rebind_alloc<
        std::pair<const Destination, MtuRecord>>;
    std::unordered_map<
        Destination, MtuRecord, HashDest, std::equal_to<Destination>, MapAlloc> m_mtu;

public:
    /// \param firstHopMtu Local AS internal MTU. Path MTUs can never be larger
    /// than this value. Usually this is to the MTU of the local AS obtained
    /// from the SCION daemon, or to the link MTU of the interface used to
    /// communicate with SCION border routers. If neither is known, a safe
    /// choice is the minimum MTU for the underlay protocol (576 bytes in IPv4,
    /// 1280 bytes in IPv6).
    explicit PathMtuDiscoverer(std::uint16_t firstHopMtu = 65500)
        : m_maximumMtu(firstHopMtu)
    {}

    /// \brief Set the MTU of the local AS. This MTU is used as the default
    /// starting value for MTU discovery.
    void setFirstHopMtu(std::uint16_t firstHopMtu)
    {
        m_maximumMtu = firstHopMtu;
    }

    /// \brief Returns the Path MTU for the given destination host and SCION
    /// path.
    template <typename Path>
    std::uint16_t getMtu(const generic::IPAddress& dest, const Path& path)
    {
        Destination d{ScIPAddress{path.lastAS(), dest}, path.digest()};
        if (auto iter = m_mtu.find(d); iter != m_mtu.end()) {
            return iter->second.mtu;
        } else {
            return m_maximumMtu;
        }
    }

    /// \brief Returns the Path MTU for the given destination host and SCION
    /// path.
    std::uint16_t getMtu(const generic::IPAddress& dest, const Path& path)
    {
        Destination d{ScIPAddress{path.lastAS(), dest}, path.digest()};
        if (auto iter = m_mtu.find(d); iter != m_mtu.end()) {
            return iter->second.mtu;
        } else {
            std::uint16_t mtu = path.mtu();
            if (mtu == 0) { // mtu is 0 if no path metadata is available
                mtu = m_maximumMtu;
            }
            m_mtu[d] = MtuRecord{mtu};
            return mtu;
        }
    }

    /// \brief Update a Path MTU with a new value. The MTU of a path that is
    /// already known can only be lowered or kept at the current value, not
    /// increased.
    /// \return Returns true if the PMTU was successfully updated. False is
    /// returned if the new MTU value is greater than the last known value.
    template <typename Path>
    bool updateMtu(const generic::IPAddress& dest, const Path& path, std::uint16_t mtu)
    {
        Destination d{ScIPAddress{path.lastAS(), dest}, path.digest()};
        return updateMtu(d, mtu);
    }

    /// \brief Remove a destination's PMTU record.
    template <typename Path>
    void forgetMtu(const generic::IPAddress& dest, const Path& path)
    {
        Destination d{ScIPAddress{path.lastAS(), dest}, path.digest()};
        m_mtu.erase(d);
    }

    bool handleScmpCallback(
        const ScIPAddress& from,
        const RawPath& path,
        const hdr::ScmpMessage& msg,
        std::span<const std::byte> payload) override
    {
        // FIXME: Forged SCMP messages can quickly fill up the map.
        if (auto v = std::get_if<hdr::ScmpPacketTooBig>(&msg)) {
            if (auto dest = parseScmpPacketQuote(payload); dest) {
                updateMtu(*dest, v->mtu);
            }
        } else if (auto v = std::get_if<hdr::ScmpParamProblem>(&msg)) {
            if (v->code == hdr::ScmpParamProblem::Code::InvalidSize) {
                if (auto dest = parseScmpPacketQuote(payload); dest) {
                    // The Go border router never responds with PacketTooBig,
                    // but consistently returns ParameterProblem errors when the
                    // MTU approaches 9000 bytes, 8000 seems like a safe choice
                    // in this case.
                    updateMtu(*dest, 8000);
                }
            }
        }
        return true; // give other handlers a chance to handle PacketTooBig as well
    }

private:
    bool updateMtu(const Destination& dest, std::uint16_t mtu)
    {
        if (auto iter = m_mtu.find(dest); iter != m_mtu.end()) {
            if (iter->second.mtu >= mtu) {
                iter->second.mtu = mtu;
                return true;
            } else {
                return false;
            }
        } else {
            m_mtu[dest] = MtuRecord{mtu};
            return true;
        }
    }

    std::optional<Destination> parseScmpPacketQuote(std::span<const std::byte> pktQuote)
    {
        ReadStream rs(pktQuote);
        SCION_STREAM_ERROR err;
        hdr::SCION sci;
        if (!sci.serialize(rs, err)) {
            SCION_DEBUG_PRINT("Error parsing SCMP packet quote:\n" << err);
            return std::nullopt;
        }
        std::span<const std::byte> path;
        if (!rs.lookahead(path, sci.pathSize(), err)) {
            SCION_DEBUG_PRINT("Error parsing SCMP packet quote:\n" << err);
            return std::nullopt;
        }
        RawPath rp(sci.src.isdAsn(), sci.dst.isdAsn(), sci.ptype, path);
        return Destination{sci.dst, rp.digest()};
    }
};

} // namespace scion
