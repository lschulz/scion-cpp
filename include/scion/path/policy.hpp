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

#include "scion/path/path.hpp"

#include <boost/json.hpp>

#include <filesystem>
#include <regex>
#include <string_view>
#include <string>
#include <vector>


namespace scion {
namespace path_policy {

/// \brief Matches packet 5-tuples plus traffic class. Zero fields match any
/// value. Elements of ScIPEndpoint may be replaced with zero from right to
/// left, i.e. in order port, IP, ASN, ISD.
class TrafficMatcher
{
private:
    ScIPEndpoint m_src;
    ScIPEndpoint m_dst;
    hdr::ScionProto m_proto = hdr::ScionProto(0);
    std::uint8_t m_trafficClass = 0;

public:
    TrafficMatcher() = default;
    TrafficMatcher(ScIPEndpoint src, ScIPEndpoint dst, hdr::ScionProto proto, std::uint8_t tc)
        : m_src(src), m_dst(dst), m_proto(proto), m_trafficClass(tc)
    {}

    bool match(ScIPEndpoint src, ScIPEndpoint dst, hdr::ScionProto proto, std::uint8_t tc) const
    {
        if (!matchEp(m_src, src)) return false;
        if (!matchEp(m_dst, dst)) return false;
        if ((std::uint8_t)m_proto && m_proto != proto) return false;
        if (m_trafficClass && m_trafficClass != tc) return false;
        return true;
    }

private:
    friend class PolicySet;

    TrafficMatcher(const boost::json::object& obj);
    static ScIPEndpoint parseAddressMatcher(const boost::json::string& str);
    static bool matchEp(ScIPEndpoint matcher, ScIPEndpoint value);
};

/// \brief A hop predicate as specified in [Hop Predicate][hp].
/// [hp]: https://docs.scion.org/en/latest/dev/design/Policy.html#hop-predicate-hp
class HopPredicate
{
private:
    IsdAsn m_isdAsn;
    path_meta::Interface m_ingress = 0;
    path_meta::Interface m_egress = 0;

public:
    HopPredicate() = default;
    HopPredicate(IsdAsn isdAsn, path_meta::Interface ingress, path_meta::Interface egress)
        : m_isdAsn(isdAsn), m_ingress(ingress), m_egress(egress)
    {}

    /// \brief Construct a hop predicate from the string representation in the
    /// form "ISD-ASN#Ig,Eg". Shorthand forms are supported.
    static Maybe<HopPredicate> Parse(std::string_view sv);

    /// \brief Returns true if the predicate matches the given hop.
    bool match(IsdAsn isdAsn, path_meta::Interface ingress, path_meta::Interface egress) const
    {
        if (!m_isdAsn.isd().isUnspecified()) {
            if (m_isdAsn.isd() != isdAsn.isd()) return false;
        }
        if (!m_isdAsn.asn().isUnspecified()) {
            if (m_isdAsn.asn() != isdAsn.asn()) return false;
        }
        if (m_ingress) {
            if (m_egress) {
                if (ingress != m_ingress || egress != m_egress) return false;
            } else {
                if (ingress != m_ingress && egress != m_ingress) return false;
            }
        }
        return true;
    }

    /// \brief Turns the string predicate into a regular expression that can be
    /// matched against the full "ISD-ASN#Ig,Eg" form of a hop.
    std::string regex() const;
};

namespace details {
std::string interfacesToSeqExpr(const path_meta::Interfaces& ifaces);
Maybe<std::regex> translateHopSeqExprToRegex(std::string_view seq);
}

/// \brief Pase class for path requirements.
class PathRequirement
{
public:
    virtual ~PathRequirement() = default;
    virtual bool fullfills(const Path& path) const = 0;
};

/// \brief Requires a minimum metadata path mtu. The discovered path MTU is not
/// constrained.
class MinMetaMtu : public PathRequirement
{
private:
    std::uint16_t minMtu = 0;

public:
    MinMetaMtu() = default;
    /// \param min Minimum Path MTU.
    explicit MinMetaMtu(std::uint16_t min) : minMtu(min) {}
    bool fullfills(const Path& path) const override;
};

/// \brief Requires metadata path latency to be below a maximum value.
class MaxMetaLat : public PathRequirement
{
private:
    scion::path_meta::Duration maxLat = std::chrono::nanoseconds(0);

public:
    MaxMetaLat() = default;
    /// \param max Maximum latency.
    explicit MaxMetaLat(scion::path_meta::Duration max) : maxLat(max) {}
    bool fullfills(const Path& path) const override;
};

/// \brief Requires metadata path bandwidth to be above a minimum value.
class MinMetaBw : public PathRequirement
{
private:
    std::uint64_t minBw = 0;

public:
    MinMetaBw() = default;
    /// \param min Minimum bandwidth in kbit/s.
    explicit MinMetaBw(std::uint64_t min) : minBw(min) {}
    bool fullfills(const Path& path) const override;
};

enum class PathOrder
{
    Random,      ///< Randomize order
    HopsAsc,     ///< Ascending number of hops
    HopsDesc,    ///< Descending number of hops
    MetaLatAsc,  ///< Ascending metadata path latency
    MetaLatDesc, ///< Descending metadata path latency
    MetaBwAsc,   ///< Ascending metadata path bandwidth
    MetaBwDesc,  ///< Descending metadata path bandwidth
};

/// \brief Path policy similar to the [Path Policy Language][ppl].
/// Supports ACLs, hop sequence predicates and extending a base policy.
/// Additionally supports path metadata requirements and reordering paths.
/// [ppl]: https://docs.scion.org/en/latest/dev/design/PathPolicy.html
class Policy
{
private:
    std::shared_ptr<std::vector<std::pair<bool, HopPredicate>>> m_acl;
    std::shared_ptr<std::regex> m_sequence;
    std::shared_ptr<std::vector<std::unique_ptr<PathRequirement>>> m_reqs;
    std::shared_ptr<std::vector<PathOrder>> m_ordering;

public:
    Policy() = default;
    Policy(const boost::json::object& obj, const Policy* base);

    /// \brief Returns true if the path is allowed by the policy, otherwise
    /// false.
    bool test(const Path& path) const
    {
        if (path.empty()) return true;
        auto md = path.getAttribute<scion::path_meta::Interfaces>(PATH_ATTRIBUTE_INTERFACES);
        if (!md) return false;
        if (!checkRequirements(path)) return false;
        if (!matchACL(*md)) return false;
        if (!matchSequence(*md)) return false;
        return true;
    }

    /// \brief Filter and reorder paths in-place. Returns a subview of 'paths'
    /// that contains the range of allowed paths. The returned subview is
    /// guaranteed to start at `paths.data()` with a length smaller or equal to
    /// the original span.
    std::span<PathPtr> apply(std::span<PathPtr> paths) const
    {
        auto out = paths.begin();
        auto end = paths.end();
        for (auto i = paths.begin(); i < end; ++i)
        {
            if (test(*i->get()))
                *out++ = std::move(*i);
        }
        std::span<PathPtr> res(paths.begin(), out - paths.begin());
        sort(res);
        return res;
    }

private:
    void parseAcl(const boost::json::array& acl);
    void parseRequirements(const boost::json::object& reqs);
    void parseOrdering(const boost::json::array& order);

    bool matchACL(const path_meta::Interfaces& ifaces) const;
    bool matchSequence(const path_meta::Interfaces& ifaces) const;
    bool checkRequirements(const Path& path) const;
    void sort(std::span<PathPtr> paths) const;
};

/// \brief A set of traffic matchers and policies. Can be loaded from a JSON
/// policy file.
class PolicySet
{
private:
    static constexpr std::size_t POLICY_INDEX_NONE = -1;
    static constexpr std::size_t POLICY_INDEX_DEFAULT = -2;

    // Pairs of matcher and index into policies table.
    std::vector<std::pair<TrafficMatcher, std::size_t>> m_matchers;
    // Pairs of policies and index of the next failover policy.
    std::vector<std::pair<Policy, std::size_t>> m_policies;
    // The default policy is always present.
    Policy m_defaultPolicy;

public:
    PolicySet() = default;

    /// \brief Load policy set from a JSON-formatted file.
    /// \returns Error code and explanatory error message if the error code
    /// is not zero.
    std::pair<std::error_code, std::string> loadJsonFile(const std::filesystem::path& path);

    /// \brief Get the first policy matching flows with the given parameters.
    const Policy& getPolicy(
        ScIPEndpoint src, ScIPEndpoint dst, hdr::ScionProto proto, std::uint8_t tc) const
    {
        return getPolicyIndex(src, dst, proto, tc).first;
    }

    /// \brief Apply the matching policy to the given paths. See
    /// Policy::apply(). If the policy filters out every available path,
    /// recursively tries the "failover" policy until paths are returned or no
    /// more policies remain.
    std::span<PathPtr> apply(
        ScIPEndpoint src, ScIPEndpoint dst, hdr::ScionProto proto, std::uint8_t tc,
        std::span<PathPtr> paths) const
    {
        if (paths.empty()) return paths;
        auto [policy, next] = getPolicyIndex(src, dst, proto, tc);
        auto filtered = policy.apply(paths);
        while (filtered.empty() && next != POLICY_INDEX_NONE) {
            if (next == POLICY_INDEX_DEFAULT) {
                return m_defaultPolicy.apply(paths);
            } else {
                filtered = m_policies[next].first.apply(paths);
                next = m_policies[next].second;
            }
        }
        return filtered;
    }

private:
    std::pair<const Policy&, std::size_t> getPolicyIndex(
        ScIPEndpoint src, ScIPEndpoint dst, hdr::ScionProto proto, std::uint8_t tc) const
    {
        for (auto& [matcher, policy] : m_matchers) {
            if (matcher.match(src, dst, proto, tc) && policy < m_policies.size()) {
                return m_policies[policy];
            }
        }
        return std::pair<const Policy&, std::size_t>(m_defaultPolicy, POLICY_INDEX_NONE);
    }

    void parse(const boost::json::value& data);
};

} // namespace path_policy
} // namespace scion
