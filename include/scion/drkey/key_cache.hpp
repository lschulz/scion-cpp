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

#include "scion/addr/generic_ip.hpp"
#include "scion/addr/isd_asn.hpp"
#include "scion/drkey/drkey.hpp"

#include <algorithm>
#include <chrono>
#include <concepts>
#include <list>
#include <unordered_map>


namespace scion {
namespace drkey {

namespace concepts {
template <typename F>
concept ASHostKeyFetcher = requires(F& f,
    IsdAsn srcIA,
    const ScIPAddress& dstHost,
    DRKeyProtocol proto,
    std::chrono::system_clock::time_point validAt)
{
    { f(srcIA, dstHost, proto, validAt) } -> std::same_as<Maybe<Key>>;
};

template <typename F>
concept HostHostKeyFetcher = requires(F& f,
    const ScIPAddress& srcHost,
    const ScIPAddress& dstHost,
    DRKeyProtocol proto,
    std::chrono::system_clock::time_point validAt)
{
    { f(srcHost, dstHost, proto, validAt) } -> std::same_as<Maybe<Key>>;
};
} // namespace concepts

/// \brief Simple cache for DRKey AS-host and host-host keys.
class KeyCache
{
private:
    // Since destination host addresses must be SCION addresses of the host
    // maintaining this cache, the set of possible host addresses is usually
    // very small. We store these addresses as shared pointers to a common
    // string to save memory.
    using HostAddrPtr = std::shared_ptr<ScIPAddress>;

    struct ASHostPair
    {
        IsdAsn srcAS;
        HostAddrPtr dstHost;
    };

    struct HashASHost {
        std::size_t operator()(const ASHostPair& p) const
        {
            return std::hash<IsdAsn>{}(p.srcAS) ^ std::hash<HostAddrPtr>{}(p.dstHost);
        }
    };

    struct EqualToASHost {
        bool operator()(const ASHostPair& lhs, const ASHostPair& rhs) const
        {
            return lhs.srcAS == rhs.srcAS && lhs.dstHost == rhs.dstHost;
        }
    };

    struct HostHostPair
    {
        ScIPAddress srcHost;
        HostAddrPtr dstHost;
    };

    struct HashHostHostPair {
        std::size_t operator()(const HostHostPair& p) const
        {
            return std::hash<ScIPAddress>{}(p.srcHost) ^ std::hash<HostAddrPtr>{}(p.dstHost);
        }
    };

    struct EqualToHostHostPair {
        bool operator()(const HostHostPair& lhs, const HostHostPair& rhs) const
        {
            return lhs.srcHost == rhs.srcHost && lhs.dstHost == rhs.dstHost;
        }
    };

    // Protocol ID of all keys in this cache.
    const DRKeyProtocol m_protocol;

    // Index of known destination hosts. Usually just the SCION address of the
    // local host.
    std::list<std::weak_ptr<ScIPAddress>> m_dstHosts;

    using AsCache = std::unordered_map<
        ASHostPair, drkey::Key, HashASHost, EqualToASHost>;
    AsCache m_asCache;

    using HostCache = std::unordered_map<
        HostHostPair, drkey::Key, HashHostHostPair, EqualToHostHostPair>;
    HostCache m_hostCache;

public:
    using TimePoint = std::chrono::system_clock::time_point;

    /// \brief Create a new key cache for use with the given protocol.
    explicit KeyCache(DRKeyProtocol protocol)
        : m_protocol(protocol)
    {}

    /// \brief Get an AS-to-host key. These keys are used by SCION ASes to
    /// authenticate messages sent to hosts.
    /// \param srcAS Sender AS.
    /// \param dstHost Receiver host. Usually the SCION address of the local
    /// host.
    /// \param validAt Time at which the key must be valid.
    /// \param fetchASHostKey Called if there is no key in the cache that is
    /// valid at `validAt`. If the callback returns a new key it replaces any
    /// existing keys for the same source and destination pair.
    template <concepts::ASHostKeyFetcher F>
    Maybe<drkey::Key> getASHostKey(
        IsdAsn srcAS,
        const ScIPAddress& dstHost,
        TimePoint validAt,
        F fetchASHostKey)
    {
        ASHostPair p{srcAS, getDstHost(dstHost)};
        if (auto i = m_asCache.find(p); i != m_asCache.end()) {
            if (i->second.isValid(validAt)) {
                return i->second;
            }
        }
        auto key = fetchASHostKey(srcAS, dstHost, m_protocol, validAt);
        if (key.has_value()) {
            m_asCache[p] = *key;
        }
        return key;
    }

    /// \brief Get a host-to-host keys. These keys are used by SCION host to
    /// authenticate messages to other host in the same or in a different AS.
    /// \param srcHost Sender host.
    /// \param dstHost Receiver host. Usually the SCION address of the local host.
    /// \param validAt Time at which the key must be valid.
    /// \param fetchHostHostKey Called if there is no key in the cache that is
    /// valid at `validAt`. If the callback returns a new key it replaces any
    /// existing keys for the same source and destination pair.
    template <concepts::HostHostKeyFetcher F>
    Maybe<drkey::Key> getHostHostKey(
        const ScIPAddress& srcHost,
        const ScIPAddress& dstHost,
        TimePoint validAt,
        F fetchHostHostKey)
    {
        HostHostPair p{srcHost, getDstHost(dstHost)};
        if (auto i = m_hostCache.find(p); i != m_hostCache.end()) {
            if (i->second.isValid(validAt)) {
                return i->second;
            }
        }
        auto key = fetchHostHostKey(srcHost, dstHost, m_protocol, validAt);
        if (key.has_value()) {
            m_hostCache[p] = *key;
        }
        return key;
    }

    /// \brief Refresh expired AS-host keys.
    /// \param cutoff Keys that are not valid at this time point are replaced.
    /// \param validAt Desired validity of new keys. Passed to fetchASHostKey().
    /// \param fetchASHostKey Callback that fetches the new keys.
    /// \returns The number of successfully replaced keys.
    template <concepts::ASHostKeyFetcher F>
    std::size_t refreshASHostKeys(TimePoint cutoff, TimePoint validAt, F fetchASHostKey)
    {
        std::size_t n = 0;
        auto end = m_asCache.end();
        for (auto i = m_asCache.begin(); i != end; ++i) {
            if (!i->second.isValid(cutoff)) {
                auto key = fetchASHostKey(
                    i->first.srcAS, *i->first.dstHost, m_protocol, validAt);
                if (key.has_value()) {
                    i->second = *key;
                    ++n;
                }
            }
        }
        return n;
    }

    /// \brief Refresh expired host-host keys.
    /// \param cutoff Keys that are not valid at this time point are replaced.
    /// \param validAt Desired validity of new keys. Passed to fetchASHostKey().
    /// \param fetchHostHostKey Callback that fetches the new keys.
    /// \returns The number of successfully replaced keys.
    template <concepts::HostHostKeyFetcher F>
    std::size_t refreshHostHostKeys(TimePoint cutoff, TimePoint validAt, F fetchHostHostKey)
    {
        std::size_t n = 0;
        auto end = m_hostCache.end();
        for (auto i = m_hostCache.begin(); i != end; ++i) {
            if (!i->second.isValid(cutoff)) {
                auto key = fetchHostHostKey(
                    i->first.srcHost, *i->first.dstHost, m_protocol, validAt);
                if (key.has_value()) {
                    i->second = *key;
                    ++n;
                }
            }
        }
        return n;
    }

    /// \brief Returns the number of cached AS-host keys.
    std::size_t countASHostKeys()
    {
        return m_asCache.size();
    }

    /// \brief Returns the number of cached host-host keys.
    std::size_t countHostHostKeys()
    {
        return m_hostCache.size();
    }

    /// \brief Forget all keys.
    void clear()
    {
        m_asCache.clear();
        clearHostHostKey();
        m_dstHosts.clear();
    }

    /// \brief Forgat all host-host keys, bit keep the ASHost keys.
    void clearHostHostKey()
    {
        m_hostCache.clear();
        clearExpiredHosts();
    }

    /// \brief Clear all keys that are not valid at `now` from the cache.
    void clearExpired(TimePoint now)
    {
        std::erase_if(m_asCache, [&](const AsCache::value_type& p) {
            return !p.second.isValid(now);
        });
        std::erase_if(m_hostCache, [&](const HostCache::value_type& p) {
            return !p.second.isValid(now);
        });
        clearExpiredHosts();
    }

private:
    HostAddrPtr getDstHost(const ScIPAddress& dstHost)
    {
        for (auto& ptr : m_dstHosts) {
            auto host = ptr.lock();
            if (*host == dstHost)
                return host;
        }
        auto host = std::make_shared<ScIPAddress>(dstHost);
        m_dstHosts.emplace_front(host);
        return host;
    }

    void clearExpiredHosts()
    {
        std::erase_if(m_dstHosts, [](const std::weak_ptr<ScIPAddress>& p) {
            return p.expired();
        });
    }
};

} // namespace drkey
} // namespace scion
