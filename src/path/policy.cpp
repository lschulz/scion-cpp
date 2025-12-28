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

#include "scion/details/from_chars.hpp"
#include "scion/path/policy.hpp"

#include <algorithm>
#include <format>
#include <fstream>
#include <limits>
#include <random>
#include <sstream>
#include <stdexcept>


namespace scion {
namespace path_policy {

class ParserError : public std::runtime_error
{
public:
    using std::runtime_error::runtime_error;
};

static boost::json::string_view ltrim(boost::json::string_view sv)
{
    auto i = std::find_if_not(sv.begin(), sv.end(), [] (char c) {
        return std::isspace(c);
    });
    return sv.substr(i - sv.begin());
}

static boost::json::string_view rtrim(boost::json::string_view sv)
{
    auto i = std::find_if_not(sv.rbegin(), sv.rend(), [] (char c) {
        return std::isspace(c);
    });
    return sv.substr(0, sv.size() - (i - sv.rbegin()));
}

////////////////////
// TrafficMatcher //
////////////////////

TrafficMatcher::TrafficMatcher(const boost::json::object& obj)
{
    for (auto&& [name, value] : obj) {
        if (name == "source") {
            m_src = parseAddressMatcher(value.as_string());
        } else if (name == "destination") {
            m_dst = parseAddressMatcher(value.as_string());
        } else if (name == "protocol") {
            auto proto = value.as_string();
            if (proto == "tcp")
                m_proto = hdr::ScionProto::TCP;
            else if (proto == "udp")
                m_proto = hdr::ScionProto::UDP;
            else
                throw ParserError(std::format("Unknown protocol '{}'", proto.c_str()));
        } else if (name == "traffic_class") {
            auto tc = value.as_int64();
            if (tc < 0 || tc > std::numeric_limits<std::uint8_t>::max())
                throw ParserError("Invalid traffic class");
            m_trafficClass = (std::uint8_t)tc;
        } else if (name == "policy") {
            continue;
        } else {
            throw ParserError(std::format(
                "Matcher attribute '{}' not recognized", std::string_view(name)));
        }
    }
}

ScIPEndpoint TrafficMatcher::parseAddressMatcher(const boost::json::string& str)
{
    if (str.find(',') == str.npos) {
        // no IP part, parse as ISD-ASN
        if (auto isdAsn = IsdAsn::Parse(str); isError(isdAsn))
            throw ParserError(std::format("Invalid address matcher: '{}'", str.c_str()));
        else
            return ScIPEndpoint(*isdAsn, generic::IPEndpoint());
    } else {
        if (auto ep = ScIPEndpoint::Parse(str); isError(ep))
            throw ParserError(std::format("Invalid address matcher: '{}'", str.c_str()));
        else
            return std::move(*ep);
    }
}

bool TrafficMatcher::matchEp(ScIPEndpoint matcher, ScIPEndpoint value)
{
    auto a = matcher.isdAsn();
    auto b = value.isdAsn();
    if (!a.isd().isUnspecified()) {
        if (a.isd() != b.isd()) return false;
    } else {
        return true;
    }
    if (!a.asn().isUnspecified()) {
        if (a.asn() != b.asn()) return false;
    } else {
        return true;
    }
    if (!matcher.host().isUnspecified()) {
        if (matcher.host() != value.host()) return false;
    } else {
        return true;
    }
    if (matcher.port()) {
        if (matcher.port() != value.port()) return false;
    }
    return true;
}

//////////////////
// HopPredicate //
//////////////////

namespace details {
std::string interfacesToSeqExpr(const path_meta::Interfaces& ifaces)
{
    std::stringstream s;
    bool first = true;
    for (auto&& hop : ifaces.data) {
        if (!first) s << ' ';
        first = false;
        s << std::format("{}#{},{}", hop.isdAsn, hop.ingress, hop.egress);
    }
    return s.str();
}

Maybe<std::regex> translateHopSeqExprToRegex(std::string_view seq)
{
    try {
        static std::regex predicate(
            R"((?:(\d+-[0-9a-f-A-F]{1,4}:[0-9a-f-A-F]{1,4}:[0-9a-f-A-F]{1,4})|(\d+-\d+))(#\d+(,\d+)?)?|(\d+))");
        std::stringstream s;
        auto sv = seq;
        std::match_results<const char*> match;
        while (std::regex_search(sv.data(), sv.data() + sv.size(), match, predicate)) {
            s << rtrim(std::string_view(match.prefix().first, match.prefix().length()));
            auto hp = HopPredicate::Parse(std::string_view(match[0].first, match[0].length()));
            if (!hp) return Error(ErrorCode::SyntaxError);
            s << hp->regex();
            sv = ltrim(std::string_view(match.suffix().first, match.suffix().length()));
        }
        s << sv;
        return std::regex(s.str());
    }
    catch (const std::regex_error&) {
        return Error(ErrorCode::SyntaxError);
    }
    catch (const std::exception&) {
        return Error(ErrorCode::LogicError);
    }
}
} // namespace details

Maybe<HopPredicate> HopPredicate::Parse(std::string_view sv)
{
    using scion::details::from_chars;
    HopPredicate hp;
    if (sv.empty()) return hp;
    auto hash = sv.find('#');
    if (sv.find('-') == sv.npos) {
        std::uint16_t isd = 0;
        if (auto ec = from_chars(sv.substr(0, hash), isd); ec)
            return Error(ec);
        hp.m_isdAsn = IsdAsn(Isd(isd), Asn());
    } else {
        if (auto res = IsdAsn::Parse(sv.substr(0, hash)); isError(res))
            return propagateError(res);
        else
            hp.m_isdAsn = *res;
    }
    if (hash != sv.npos) {
        auto comma = sv.substr(hash + 1).find(',');
        auto ec = from_chars(sv.substr(hash + 1, comma), hp.m_ingress);
        if (ec) return Error(ec);
        if (comma != sv.npos) {
            ec = from_chars(sv.substr(hash + comma + 2), hp.m_egress);
            if (ec) return Error(ec);
        }
    }
    return hp;
}

std::string HopPredicate::regex() const
{
    if (m_isdAsn.isd().isUnspecified()) {
        return R"((\d+-[0-9a-f:]+#\d+,\d+\s?))";
    }
    if (m_isdAsn.asn().isUnspecified()) {
        return std::format(R"(({}-[0-9a-f:]+#\d+,\d+\s?))", m_isdAsn.isd());
    }
    if (!m_ingress) {
        return std::format(R"(({}#\d+,\d+\s?))", m_isdAsn);
    } else {
        if (!m_egress) {
            return std::format(R"(({0}#({1},\d+|\d+,{1})\s?))", m_isdAsn, m_ingress);
        } else {
            return std::format(R"(({}#{},{}\s?))", m_isdAsn, m_ingress, m_egress);
        }
    }
}

///////////////////////
// Path Requirements //
///////////////////////

static scion::path_meta::Duration getMetaLatency(const Path& path)
{
    namespace pm = scion::path_meta;
    using namespace std::chrono_literals;
    auto meta = path.getAttribute<pm::LinkMetadata>(PATH_ATTRIBUTE_LINK_META);
    if (!meta) return scion::path_meta::Duration::max();
    scion::path_meta::Duration lat = std::chrono::nanoseconds(0);
    for (auto&& link : meta->data) {
        if (link.latency == 0ns) return scion::path_meta::Duration::max();
        lat += link.latency;
    }
    return lat;
}

static std::uint64_t getMetaBw(const Path& path)
{
    namespace pm = scion::path_meta;
    auto meta = path.getAttribute<pm::LinkMetadata>(PATH_ATTRIBUTE_LINK_META);
    if (!meta) return 0;
    std::uint64_t bw = -1;
    for (auto&& link : meta->data) {
        if (link.bandwidth == 0) return 0;
        bw = std::min(bw, link.bandwidth);
    }
    return bw;
}

bool MinMetaMtu::fullfills(const Path& path) const
{
    return path.mtu() >= minMtu;
}

bool MaxMetaLat::fullfills(const Path& path) const
{
    return getMetaLatency(path) <= maxLat;
}

bool MinMetaBw::fullfills(const Path& path) const
{

    return getMetaBw(path) >= minBw;
}

////////////
// Policy //
////////////

Policy::Policy(const boost::json::object& obj, const Policy* base)
{
    // Parse JSON
    for (auto&& [name, value] : obj) {
        if (name == "acl") {
            parseAcl(value.as_array());
        } else if (name == "sequence") {
            if (auto seq = details::translateHopSeqExprToRegex(value.as_string()); seq)
                m_sequence = std::make_shared<std::regex>(std::move(*seq));
            else
                throw ParserError(std::format("Can't interpret hop predicate sequence '{}'",
                    value.as_string().c_str()));
        } else if (name == "requirements") {
            parseRequirements(value.as_object());
        } else if (name == "ordering") {
            parseOrdering(value.as_array());
        } else if (name == "extends" || name == "failover") {
            continue;
        } else {
            throw ParserError(std::format(
                "Policy attribute '{}' not recognized", std::string_view(name)));
        }
    }

    // Inherit undefined attributes from base
    if (base) {
        if (!m_acl) m_acl = base->m_acl;
        if (!m_sequence) m_sequence = base->m_sequence;
        if (!m_reqs) m_reqs = base->m_reqs;
        if (!m_ordering) m_ordering = base->m_ordering;
    }
}

void Policy::parseAcl(const boost::json::array& acl)
{
    m_acl = std::make_shared<std::vector<std::pair<bool, HopPredicate>>>();
    m_acl->reserve(acl.size());
    for (auto&& entry : acl) {
        auto line = entry.as_string();
        if (line.starts_with('+')) {
            if (auto hp = HopPredicate::Parse(ltrim(line.subview(1))); hp)
                m_acl->push_back(std::make_pair(true, std::move(*hp)));
            else
                throw ParserError(std::format("Invalid hop predicate '{}'", line.c_str()));
        } else if (line.starts_with('-')) {
            if (auto hp = HopPredicate::Parse(ltrim(line.subview(1))); hp)
                m_acl->push_back(std::make_pair(false, std::move(*hp)));
            else
                throw ParserError(std::format("Invalid hop predicate '{}'", line.c_str()));
        } else {
            throw ParserError("ACL line must start with + or -");
        }
    }
}

void Policy::parseRequirements(const boost::json::object& reqs)
{
    m_reqs = std::make_shared<std::vector<std::unique_ptr<PathRequirement>>>();
    m_reqs->reserve(reqs.size());
    for (auto&& [name, value] : reqs) {
        if (name == "min_mtu") {
            m_reqs->push_back(std::make_unique<MinMetaMtu>(
                (std::uint16_t)std::min<std::uint64_t>(value.as_int64(), 65535)
            ));
        } else if (name == "max_meta_lat") {
            m_reqs->push_back(std::make_unique<MaxMetaLat>(
                std::chrono::milliseconds(value.as_int64())
            ));
        } else if (name == "min_meta_bw") {
            m_reqs->push_back(std::make_unique<MinMetaBw>(value.as_int64()));
        } else {
            throw ParserError(std::format(
                "Requirement '{}' not recognized", std::string_view(name)));
        }
    }
}

void Policy::parseOrdering(const boost::json::array& order)
{
    m_ordering = std::make_shared<std::vector<PathOrder>>();
    m_ordering->reserve(order.size());
    for (auto&& value : order) {
        auto ordering = value.as_string();
        if (ordering == "random") {
            m_ordering->push_back(PathOrder::Random);
        } else if (ordering == "hops_asc") {
            m_ordering->push_back(PathOrder::HopsAsc);
        } else if (ordering == "hops_desc") {
            m_ordering->push_back(PathOrder::HopsDesc);
        } else if (ordering == "meta_latency_asc") {
            m_ordering->push_back(PathOrder::MetaLatAsc);
        } else if (ordering == "meta_latency_desc") {
            m_ordering->push_back(PathOrder::MetaLatDesc);
        } else if (ordering == "meta_bandwidth_asc") {
            m_ordering->push_back(PathOrder::MetaBwAsc);
        } else if (ordering == "meta_bandwidth_desc") {
            m_ordering->push_back(PathOrder::MetaBwDesc);
        } else {
            throw ParserError(std::format(
                "Ordering '{}' not recognized", ordering.c_str()));
        }
    }
}

bool Policy::matchACL(const path_meta::Interfaces& ifaces) const
{
    if (!m_acl) return true;
    for (auto&& hop : ifaces.data) {
        for (auto&& [allow, hp] : *m_acl) {
            if (hp.match(hop.isdAsn, hop.ingress, hop.egress)) {
                return allow;
            }
        }
    }
    return false;
}

bool Policy::matchSequence(const path_meta::Interfaces& ifaces) const
{
    if (!m_sequence) return true;
    return std::regex_match(details::interfacesToSeqExpr(ifaces), *m_sequence);
}

bool Policy::checkRequirements(const Path& path) const
{
    if (!m_reqs) return true;
    for (auto&& req : *m_reqs) {
        if (!req->fullfills(path)) return false;
    }
    return true;
}

void Policy::sort(std::span<PathPtr> paths) const
{
    if (!m_ordering) return;
    for (auto ordering : *m_ordering) {
        switch (ordering) {
        case PathOrder::Random:
        {
            std::random_device seed;
            std::minstd_rand rng(seed());
            std::shuffle(paths.begin(), paths.end(), rng);
            break;
        }
        case PathOrder::HopsAsc:
            std::ranges::stable_sort(paths,
                std::less<std::uint32_t>(), [] (const PathPtr& p) {
                    return p->hopCount();
            });
            break;
        case PathOrder::HopsDesc:
            std::ranges::stable_sort(paths,
                std::greater<std::uint32_t>(), [] (const PathPtr& p) {
                    return p->hopCount();
            });
            break;
        case PathOrder::MetaLatAsc:
            std::ranges::stable_sort(paths,
                std::less<path_meta::Duration>(), [] (const PathPtr& p) {
                    return getMetaLatency(*p);
            });
            break;
        case PathOrder::MetaLatDesc:
            std::ranges::stable_sort(paths,
                std::greater<path_meta::Duration>(), [] (const PathPtr& p) {
                    return getMetaLatency(*p);
            });
            break;
        case PathOrder::MetaBwAsc:
            std::ranges::stable_sort(paths,
                std::less<std::uint64_t>(), [] (const PathPtr& p) {
                    return getMetaBw(*p);
            });
            break;
        case PathOrder::MetaBwDesc:
            std::ranges::stable_sort(paths,
                std::greater<std::uint64_t>(), [] (const PathPtr& p) {
                    return getMetaBw(*p);
            });
            break;
        }
    }
}

///////////////
// PolicySet //
///////////////

std::pair<std::error_code, std::string> PolicySet::loadJsonFile(const std::filesystem::path& path)
{
    m_matchers.clear();
    m_policies.clear();
    m_defaultPolicy = Policy();

    boost::json::parse_options opt;
    opt.allow_comments = true;
    opt.allow_trailing_commas = true;

    try {
        std::ifstream s(path);
        if (!s.is_open()) return std::make_pair(ErrorCode::FileNotFound, "file not found");
        parse(boost::json::parse(s, boost::json::storage_ptr(), opt));
    } catch (const std::exception& e) {
        return std::make_pair(ErrorCode::SyntaxError, e.what());
    }
    return std::make_pair(ErrorCode::Ok, "");
}

void PolicySet::parse(const boost::json::value& data)
{
    std::unordered_map<boost::json::string, std::size_t> policyNames;
    if (auto policies = data.as_object().if_contains("policies"); policies) {
        auto n = policies->as_object().size();
        m_policies.reserve(n);
        policyNames.reserve(n);
        for (auto&& [name, policy] : policies->as_object()) {
            auto obj = policy.as_object();
            Policy* basePolicy = nullptr;
            std::size_t nextPolicy = POLICY_INDEX_NONE;
            if (auto raw = obj.if_contains("extends"); raw) {
                auto extends = raw->as_string();
                if (extends == "default") {
                    basePolicy = &m_defaultPolicy;
                } else if (auto i = policyNames.find(extends); i != policyNames.end()) {
                    basePolicy = &m_policies[i->second].first;
                } else {
                    throw ParserError(std::format(
                        "Policy '{}' referenced before definition", extends.c_str()));
                }
            }
            if (auto raw = obj.if_contains("failover"); raw) {
                auto failover = raw->as_string();
                if (failover == "default") {
                    nextPolicy = POLICY_INDEX_DEFAULT;
                } if (auto i = policyNames.find(failover); i != policyNames.end()) {
                    nextPolicy = i->second;
                } else {
                    throw ParserError(std::format(
                        "Policy '{}' referenced before definition", failover.c_str()));
                }
            }
            if (name == "default") {
                if (nextPolicy != POLICY_INDEX_NONE) {
                    // By demanding that policies referenced in failover must be defined before the
                    // referencing policy we can guarantee that there will be no cycles. We disallow
                    // failover in the default policy, because it is automatically defined and could
                    // be referenced before its explicit definition.
                    throw ParserError("'failover' not allowed in default policy");
                }
                m_defaultPolicy = Policy(obj, basePolicy);
            } else {
                policyNames[name] = m_policies.size();
                m_policies.emplace_back(std::piecewise_construct,
                    std::forward_as_tuple(obj, basePolicy),
                    std::forward_as_tuple(nextPolicy));
            }
        }
    }

    if (auto matchers = data.as_object().if_contains("matchers"); matchers) {
        m_matchers.reserve(matchers->as_array().size());
        for (auto&& m : matchers->as_array()) {
            auto obj = m.as_object();
            std::size_t policy = -1;
            if (auto p = obj.if_contains("policy"); p) {
                if (auto i = policyNames.find(p->as_string()); i != policyNames.end())
                    policy = policyNames.at(p->as_string());
                else
                    throw ParserError(std::format(
                        "Policy '{}' referenced before definition",
                        p->as_string().c_str()));
            }
            m_matchers.emplace_back(std::make_pair(TrafficMatcher(obj), policy));
        }
    }
}

} // namespace path_policy
} // namespace scion
