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

#include "scion/addr/isd_asn.hpp"
#include "scion/path/path.hpp"
#include "scion/scmp/handler.hpp"

#include <chrono>
#include <concepts>
#include <span>
#include <unordered_map>
#include <vector>


namespace scion {

struct PathCacheOptions
{
    /// \brief Minimum remaining path lifetime for a new path to be accepted
    /// into the cache.
    std::chrono::utc_clock::duration minAcceptedLifetime;
    /// \brief Remaining path lifetime at which paths are refreshed.
    std::chrono::utc_clock::duration refreshAtRemaining;
    /// \brief Minimum path refresh interval. Paths are refreshed in this
    /// interval even if the would not expire within `refreshAtRemaining`.
    std::chrono::utc_clock::duration refreshInterval;
};

/// \brief Container for path that keeps track of path expiration times and
/// requests path refreshes through a callback when necessary.
/// A thread-safe version is available as SharedPathCache.
class PathCache : public ScmpHandlerImpl
{
protected:
    struct Route
    {
        IsdAsn src, dst;
        bool operator==(const Route&) const = default;
    };

    struct RouteHasher
    {
        std::size_t operator()(const Route& r) const noexcept
        {
            std::hash<IsdAsn> h;
            return h(r.src) ^ h(r.dst);
        }
    };

    struct PathSet
    {
        Path::Expiry nextRefresh;
        bool refreshPending = false; // flag preventing multiple calls to path query callback
        std::vector<PathPtr> paths;
    };

    using Cache = std::unordered_map<Route, PathSet, RouteHasher>;

    std::chrono::utc_clock::duration minAcceptedLifetime;
    std::chrono::utc_clock::duration refreshAtRemaining;
    std::chrono::utc_clock::duration refreshInterval;
    Cache cache;

    friend class SharedPathCache;

public:
    PathCache()
    {
        using namespace std::chrono_literals;
        minAcceptedLifetime = 5min;
        refreshAtRemaining = 10min;
        refreshInterval = 30min;
    }

    explicit PathCache(const PathCacheOptions& opts)
        : minAcceptedLifetime(opts.minAcceptedLifetime)
        , refreshAtRemaining(opts.refreshAtRemaining)
        , refreshInterval(opts.refreshInterval)
    {}

    /// \brief Look up paths in the cache. May request paths from the path
    /// provider if the cache is empty or if the cached paths expire soon.
    ///
    /// \param src Source AS
    /// \param dst Destination AS
    /// \param queryPaths Callback that is invoked to query paths. May return
    /// ErrorCode::Pending if paths are fetched asynchronously. Paths must be
    /// written to the cache using the store() method. Signature:
    /// `std::error_code queryPaths(PathCache&, IsdAsn src, IsdAsn dst)`
    ///
    /// \returns Paths or ErrorCode::Pending if no paths are in the cache, but a
    /// path query is still pending.
    template <typename PathProvider>
    requires std::invocable<PathProvider, PathCache&, IsdAsn, IsdAsn>
    Maybe<std::vector<PathPtr>> lookup(
        IsdAsn src, IsdAsn dst, PathProvider queryPaths)
    {
        bool refresh = false;
        Maybe<std::vector<PathPtr>> paths; // for NRVO

        Route r{src, dst};
        if (auto i = cache.find(r); i != cache.end()) {
            refresh = !(i->second.refreshPending)
                && (i->second.nextRefresh < std::chrono::utc_clock::now());
            i->second.refreshPending = refresh;
        } else {
            refresh = true;
            cache[r].refreshPending = true;
        }

        std::error_code ec = ErrorCode::Ok;
        if (refresh) {
            if (src != dst)
                ec = queryPaths(*this, src, dst);
            else
                store(src, dst, std::array<PathPtr, 1>{makeEmptyPath(src)});
        }

        if (auto i = cache.find(r); i != cache.end() && !i->second.paths.empty()) {
            paths = returnValidPaths(i);
        } else {
            if (ec == ErrorCondition::Pending)
                paths = Error(ErrorCode::Pending);
        }

        return paths;
    }

    /// \brief Look up paths in the cache. May request paths from the path
    /// provider if the cache is empty or if the cached paths expire soon.
    ///
    /// \param src Source AS
    /// \param dst Destination AS
    /// \param receive Callback that is invoked if there are matching paths in
    /// the cache. Signature: `void receive(std::ranges::forward_range auto&&)`
    /// \param queryPaths Callback that is invoked to query paths. May return
    /// ErrorCode::Pending if paths are fetched asynchronously. Paths must be
    /// written to the cache using the store() method. Signature:
    /// `std::error_code queryPaths(PathCache&, IsdAsn src, IsdAsn dst)`
    ///
    /// \returns ErrorCode::Ok if successful (even if there are no paths).
    /// ErrorCode::Pending if no paths are in the cache, but a path query is
    /// still pending.
    template <typename PathReceiver, typename PathProvider>
    requires std::invocable<PathProvider, PathCache&, IsdAsn, IsdAsn>
    std::error_code lookup(IsdAsn src, IsdAsn dst, PathReceiver receive, PathProvider queryPaths)
    {
        bool refresh = false;

        Route r{src, dst};
        if (auto i = cache.find(r); i != cache.end()) {
            refresh = !(i->second.refreshPending)
                && (i->second.nextRefresh < std::chrono::utc_clock::now());
            i->second.refreshPending = refresh;
        } else {
            refresh = true;
            cache[r].refreshPending = true;
        }

        std::error_code ec = ErrorCode::Ok;
        if (refresh) {
            if (src != dst)
                ec = queryPaths(*this, src, dst);
            else
                store(src, dst, std::array<PathPtr, 1>{makeEmptyPath(src)});
        }

        if (auto i = cache.find(r); i != cache.end() && !i->second.paths.empty()) {
            auto now = std::chrono::utc_clock::now();
            receive(i->second.paths | std::views::filter([now] (const auto& path) {
                return path->expiry() > now;
            }) | std::views::as_const);
        } else {
            if (ec == ErrorCondition::Pending)
                return ErrorCode::Pending;
        }
        return ErrorCode::Ok;
    }

    /// \brief Look up paths in the cache. Never queries new paths.
    /// \param src Source AS
    /// \param dst Destination AS
    std::vector<PathPtr> lookupCached(IsdAsn src, IsdAsn dst) const
    {
        Route r{src, dst};
        if (auto i = cache.find(r); i != cache.end())
            return returnValidPaths(i);
        else
            return std::vector<PathPtr>{};
    }

    /// \brief Look up paths in the cache. Never queries new paths.
    /// \param src Source AS
    /// \param dst Destination AS
    /// \param receive Callback that is invoked if there are matching paths in
    /// the cache. Signature: `void receive(std::ranges::forward_range auto&&)`
    template <typename PathReceiver>
    void lookupCached(IsdAsn src, IsdAsn dst, PathReceiver receive) const
    {
        Route r{src, dst};
        if (auto i = cache.find(r); i != cache.end()) {
            auto now = std::chrono::utc_clock::now();
            receive(i->second.paths | std::views::filter([now] (const auto& path) {
                return path->expiry() > now;
            }) | std::views::as_const);
        }
    }

    /// \brief Replace paths from `src` to `dst` with a new set of paths.
    template <typename T>
    requires std::ranges::range<T>
        && std::same_as<std::ranges::range_value_t<T>, PathPtr>
    void store(IsdAsn src, IsdAsn dst, const T& paths)
    {
        auto now = std::chrono::utc_clock::now();
        Route r{src, dst};
        auto& cached = cache[r];
        cached.paths.clear();
        if constexpr (std::ranges::sized_range<T>) {
            cached.paths.reserve(std::ranges::size(paths));
        }
        std::ranges::copy_if(paths, std::back_inserter(cached.paths), [this, now] (const auto& path) {
            return path->expiry() > now + minAcceptedLifetime;
        });
        updateNextRefresh(now, cached);
    }

    /// \brief Replace paths from `src` to `dst` with a new set of paths.
    void store(IsdAsn src, IsdAsn dst, std::vector<PathPtr>&& paths)
    {
        auto now = std::chrono::utc_clock::now();
        Route r{src, dst};
        auto& cached = cache[r];
        cached.paths = std::move(paths);
        std::erase_if(cached.paths, [this, now] (const auto& path) {
            return path->expiry() <= now + minAcceptedLifetime;
        });
        updateNextRefresh(now, cached);
    }

    /// \brief Delete all cache entries.
    void clear()
    {
        cache.clear();
    }

    /// \brief Delete all paths from `src` to `dst`.
    void clear(IsdAsn src, IsdAsn dst)
    {
        cache.erase(Route{src, dst});
    }

    bool handleScmpCallback(
        const ScIPAddress& from,
        const RawPath& path,
        const hdr::ScmpMessage& msg,
        std::span<const std::byte> payload) override
    {
        if (auto v = std::get_if<hdr::ScmpExtIfDown>(&msg)) {
            for (auto& entry : cache) {
                for (auto& path : entry.second.paths) {
                    if (path->containsInterface(v->sender, v->iface)) {
                        path->setBroken(true);
                    }
                }
            }
        } else if (auto v = std::get_if<hdr::ScmpIntConnDown>(&msg)) {
            for (auto& entry : cache) {
                for (auto& path : entry.second.paths) {
                    if (path->containsHop(v->sender, v->ingress, v->egress)) {
                        path->setBroken(true);
                    }
                }
            }
        }
        return true;
    }

private:
    void updateNextRefresh(std::chrono::utc_clock::time_point now, PathSet& set)
    {
        auto nextExpiry = std::chrono::utc_clock::time_point::max();
        for (auto& path : set.paths) {
            nextExpiry = std::min(path->expiry(), nextExpiry);
        }
        set.nextRefresh = std::min(nextExpiry - refreshAtRemaining, now + refreshInterval);
        set.refreshPending = false;
    }

    std::vector<PathPtr> returnValidPaths(Cache::const_iterator i) const
    {
        std::vector<PathPtr> v;
        v.reserve(i->second.paths.size());
        auto now = std::chrono::utc_clock::now();
        std::ranges::copy_if(i->second.paths, std::back_inserter(v), [now] (auto& path) {
            return path->expiry() > now;
        });
        return v;
    }
};

} // namespace scion
