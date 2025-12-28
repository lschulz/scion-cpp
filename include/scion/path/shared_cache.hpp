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

#include "scion/path/cache.hpp"

#include <shared_mutex>


namespace scion {

/// \brief A version of PathCache that can be shared between multiple theads.
class SharedPathCache : public ScmpHandler
{
private:
    PathCache inner;
    mutable std::shared_mutex mutex;

public:
    SharedPathCache() = default;

    explicit SharedPathCache(const PathCacheOptions& opts)
        : inner(opts)
    {}

    /// \copydoc PathCache::lookup(IsdAsn, IsdAsn, PathProvider, bool)
    template <typename PathProvider>
    requires std::invocable<PathProvider, SharedPathCache&, IsdAsn, IsdAsn>
    Maybe<std::vector<PathPtr>> lookup(IsdAsn src, IsdAsn dst, PathProvider queryPaths)
    {
        Maybe<std::vector<PathPtr>> paths; // for NRVO

        PathCache::Route r{src, dst};
        auto ec = update(r, std::forward<PathProvider>(queryPaths));

        if (auto i = inner.cache.find(r); i != inner.cache.end() && !i->second.paths.empty()) {
            std::shared_lock<std::shared_mutex> lock(mutex);
            paths = inner.returnValidPaths(i);
        } else {
            if (ec == ErrorCondition::Pending)
                paths = Error(ErrorCode::Pending);
        }
        return paths;
    }

    /// \copydoc PathCache::lookup(IsdAsn, IsdAsn, PathReceiver, PathProvider)
    template <typename PathReceiver, typename PathProvider>
    requires std::invocable<PathProvider, SharedPathCache&, IsdAsn, IsdAsn>
    std::error_code lookup(IsdAsn src, IsdAsn dst, PathReceiver receive, PathProvider queryPaths)
    {
        PathCache::Route r{src, dst};
        auto ec = update(r, std::forward<PathProvider>(queryPaths));

        if (auto i = inner.cache.find(r); i != inner.cache.end() && !i->second.paths.empty()) {
            auto now = std::chrono::utc_clock::now();
            std::shared_lock<std::shared_mutex> lock(mutex);
            receive(i->second.paths | std::views::filter([now] (const auto& path) {
                return path->expiry() > now;
            }) | std::views::as_const);
        } else {
            if (ec == ErrorCondition::Pending)
                return ErrorCode::Pending;
        }
        return ErrorCode::Ok;
    }

    /// \copydoc PathCache::prefetch(IsdAsn, IsdAsn, PathProvider)
    template <typename PathProvider>
    requires std::invocable<PathProvider, SharedPathCache&, IsdAsn, IsdAsn>
    std::error_code prefetch(IsdAsn src, IsdAsn dst, PathProvider queryPaths, bool refresh = false)
    {
        return update(PathCache::Route{src, dst}, std::forward<PathProvider>(queryPaths), refresh);
    }

    /// \brief Look up paths in the cache. Never queries new paths.
    /// \param src Source AS
    /// \param dst Destination AS
    std::vector<PathPtr> lookupCached(IsdAsn src, IsdAsn dst) const
    {
        std::shared_lock<std::shared_mutex> lock(mutex);
        return inner.lookupCached(src, dst);
    }

    /// \brief Look up paths in the cache. Never queries new paths.
    /// \param src Source AS
    /// \param dst Destination AS
    /// \param receive Callback that is invoked if there are matching paths in
    /// the cache. Signature: `void receive(std::ranges::forward_range auto&&)`
    template <typename PathReceiver>
    void lookupCached(IsdAsn src, IsdAsn dst, PathReceiver receive) const
    {
        std::shared_lock<std::shared_mutex> lock(mutex);
        return inner.lookupCached(src, dst, receive);
    }

    /// \copydoc PathCache::store(IsdAsn, IsdAsn, const T&)
    template <typename T>
    requires std::ranges::range<T>
        && std::same_as<std::ranges::range_value_t<T>, PathPtr>
    void store(IsdAsn src, IsdAsn dst, const T& paths)
    {
        std::unique_lock<std::shared_mutex> lock(mutex);
        inner.store(src, dst, paths);
    }

    /// \brief Replace paths from `src` to `dst` with a new set of paths.
    void store(IsdAsn src, IsdAsn dst, std::vector<PathPtr>&& paths)
    {
        std::unique_lock<std::shared_mutex> lock(mutex);
        inner.store(src, dst, std::move(paths));
    }

    /// \copydoc PathCache::clear()
    void clear()
    {
        std::unique_lock<std::shared_mutex> lock(mutex);
        inner.clear();
    }

    /// \copydoc PathCache::clear(IsdAsn, IsdAsn)
    void clear(IsdAsn src, IsdAsn dst)
    {
        std::unique_lock<std::shared_mutex> lock(mutex);
        inner.clear(src, dst);
    }

    bool handleScmpCallback(
        const ScIPAddress& from,
        const RawPath& path,
        const hdr::ScmpMessage& msg,
        std::span<const std::byte> payload) override
    {
        std::unique_lock<std::shared_mutex> lock(mutex);
        return inner.handleScmpCallback(from, path, msg, payload);
    }

    ScmpHandler* nextScmpHandler() override
    {
        return inner.nextScmpHandler();
    }

    void setNextScmpHandler(ScmpHandler* handler) override
    {
        inner.setNextScmpHandler(handler);
    }

private:
    template <typename PathProvider>
    std::error_code update(const PathCache::Route& r, PathProvider queryPaths, bool refresh = false)
    {
        {
            std::unique_lock<std::shared_mutex> lock(mutex);
            if (auto i = inner.cache.find(r); i != inner.cache.end()) {
                if (!refresh) {
                    refresh = !(i->second.refreshPending)
                        && (i->second.nextRefresh < std::chrono::utc_clock::now());
                }
                i->second.refreshPending = refresh;
            } else {
                refresh = true;
                inner.cache[r].refreshPending = true;
            }
        }
        if (refresh) {
            if (r.src != r.dst)
                return queryPaths(*this, r.src, r.dst);
            else
                store(r.src, r.dst, std::array<PathPtr, 1>{makeEmptyPath(r.src)});
        }
        return ErrorCode::Ok;
    }
};

} // namespace scion
