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
#include "scion/error_codes.hpp"

#include <boost/asio.hpp>

#include <filesystem>
#include <memory>
#include <string_view>
#include <type_traits>
#include <vector>


namespace scion {

extern const char* HOSTS_FILE;

const std::error_category& cares_error_category();

/// \brief Looks up a domain name in a file formatted in the same way as
/// `/etc/hosts`.
Maybe<std::vector<ScIPAddress>> queryHostsFile(
    std::string_view name, const std::filesystem::path& hostsFilePath = HOSTS_FILE);

/// \brief Resolves host names to SCION host addresses.
///
/// Resolves names by attempting the following steps in order. Returns after the
/// first successful step, i.e., if a name appears in the hosts file, only
/// addresses from the hosts file are returned and no DNS query is performed.
/// Likewise, "localhost" or (valid) numerical address string can't be redefined
/// in the hosts file and will never trigger a DNS query.
///
/// 1. If the name is "localhost", return the localhost addresses set by
///    setLocalhost(). If the set of localhosts addresses is empty or
///    setLocalhost() was never called, returns an error code matching
///    ErrorCondition::NameNotFound.
/// 2. Try to parse the name as a numerical SCION host address of the form
///    `<ISD>-<ASN>,<IP>`, e.g., `1-ff00:0:0,::1`.
/// 3. Look up the name in `/etc/scion/hosts` (Unix-like operating systems) or
///    `%ProgramFiles%\scion\hosts` (Windows). The file's location may be
///    overridden with setHostsFile().
/// 4. Query DNS TXT records associated with the name from the operating
///    system's default DNS resolver. SCION addresses are parsed from TXT
///    records of the form "scion=<addr>" where "<addr>" is a SCION IPv4 or IPv6
///    host address.
///
/// It is recommended to use a single Resolver instance per application.
///
/// After constructing an instance, initialize() must be called before any other
/// method.
///
class Resolver
{
public:
    using AddressSet = std::vector<ScIPAddress>;

private:
    class Ares;

    std::unique_ptr<Ares> ares;
    AddressSet localhost;
    std::string hostsFile;

public:
    Resolver();
    ~Resolver();

    /// \brief Initialize the resolver. Must be called after construction before
    /// any other method can be called. If initialize() fails, the only allowed
    /// operations are to try again or destroy the object.
    [[nodiscard]] std::error_code initialize();

    /// \brief Cancel all asynchronous queries.
    void cancel() const;

    /// \brief Define the address(es) that "localhost" should resolve to.
    void setLocalhost(const AddressSet& addresses) { localhost = addresses; }

    /// \copydoc setLocalhost(const AddressSet&)
    void setLocalhost(AddressSet&& addresses) { localhost = std::move(addresses); }

    /// \brief Set path to a file formatted similar to /etc/hosts that will be
    /// used for resolving host names.
    /// \details By default the file is /etc/scion/hosts on Unix-like systems
    /// and %ProgramFiles%\scion\hosts on Windows. Set to an empty string to
    /// disable querying the hosts file.
    void setHostsFile(std::string_view hosts) { hostsFile = hosts; }

private:
    typedef void txtCallback(void*, int, int, unsigned char*, int);
    void aresQueryTXT(const std::string& name, txtCallback* cb, void* arg) const;

    static Maybe<AddressSet> parseTxtRecords(int status, unsigned char* abuf, int alen);
    static bool parseScionRecord(std::string_view record, Maybe<AddressSet>& out);

    template <boost::asio::completion_token_for<void(Maybe<AddressSet>)> Handler>
    class QueryState
    {
    private:
        Handler m_handler;
        boost::asio::executor_work_guard<boost::asio::associated_executor_t<Handler>> m_work;

    public:
        explicit QueryState(Handler&& handler)
            : m_handler(std::move(handler))
            , m_work(boost::asio::make_work_guard(m_handler))
        {}

        static QueryState* create(Handler&& handler)
        {
            using namespace boost::asio;
            struct Deleter
            {
                using ProtoAlloc = associated_allocator_t<Handler, recycling_allocator<void>>;
                using Allocator = std::allocator_traits<ProtoAlloc>::template rebind_alloc<QueryState>;

                Allocator alloc;

                void operator()(QueryState* state)
                {
                    std::allocator_traits<decltype(alloc)>::deallocate(alloc, state, 1);
                }
            };

            Deleter d{get_associated_allocator(handler, recycling_allocator<void>())};
            std::unique_ptr<QueryState, Deleter> state(
                std::allocator_traits<decltype(d.alloc)>::allocate(d.alloc, 1), d);
            auto ptr = new (state.get()) QueryState(std::move(handler));
            state.release();
            return ptr;
        }

        static void callback(void* arg, int status, int timeouts, unsigned char* abuf, int alen)
        {
            using namespace boost::asio;
            auto self = static_cast<QueryState*>(arg);
            Maybe<AddressSet> result = parseTxtRecords(status, abuf, alen);

            // Must release allocated memory before invoking the completion handler
            auto handler = std::move(self->m_handler);
            auto work = std::move(self->m_work);
            using ProtoAlloc = associated_allocator_t<Handler, recycling_allocator<void>>;
            using Allocator = std::allocator_traits<ProtoAlloc>::template rebind_alloc<QueryState>;
            Allocator alloc = get_associated_allocator(handler, recycling_allocator<void>());
            std::allocator_traits<decltype(alloc)>::destroy(alloc, self);
            std::allocator_traits<decltype(alloc)>::deallocate(alloc, self, 1);

            // Invoke completion handler
            dispatch(work.get_executor(), bind_allocator(alloc, [
                handler = std::move(handler),
                result = std::move(result)
            ] () mutable {
                std::move(handler)(result);
            }));
        }
    };

    template <boost::asio::completion_token_for<void(Maybe<AddressSet>)> CompletionToken>
    auto resolveHostImpl(std::string_view name, CompletionToken&& token) const
    {
        using namespace boost::asio;

        auto init = [this] (
            completion_handler_for<void(Maybe<AddressSet>)> auto handler,
            std::string_view name)
        {
            // handle localhost as a special case
            if (name == "localhost") {
                auto executor = boost::asio::get_associated_executor(handler);
                if (localhost.empty()) {
                    post(bind_executor(executor, std::bind(
                        std::forward<decltype(handler)>(handler),
                        Maybe<AddressSet>{Error{ErrorCode::NameNotFound}}
                    )));
                } else {
                    post(bind_executor(executor, std::bind(
                        std::forward<decltype(handler)>(handler), Maybe<AddressSet>{localhost}
                    )));
                }
                return;
            }
            // resolve numerical addresses
            if (auto addr = ScIPAddress::Parse(name); addr.has_value()) {
                auto executor = boost::asio::get_associated_executor(handler);
                AddressSet addresses{*addr};
                post(bind_executor(executor, std::bind(
                    std::forward<decltype(handler)>(handler), Maybe<AddressSet>{std::move(addresses)}
                )));
                return;
            }
            // query hosts file
            if (!hostsFile.empty()) {
                if (auto addr = queryHostsFile(name, hostsFile.c_str()); addr.has_value()) {
                    auto executor = boost::asio::get_associated_executor(handler);
                    post(bind_executor(executor, std::bind(
                        std::forward<decltype(handler)>(handler), std::move(addr)
                    )));
                    return;
                }
            }
            // query TXT records
            using State = QueryState<decltype(handler)>;
            aresQueryTXT(std::string(name).c_str(),
                &State::callback, State::create(std::move(handler)));
        };

        return async_initiate<CompletionToken, void(Maybe<AddressSet>)>(
            init, token, name
        );
    }

public:
    /// \copydoc details::splitHostPort()
    static Maybe<std::pair<std::string_view, std::uint16_t>> splitHostPort(std::string_view name)
    {
        return details::splitHostPort(name);
    }

    /// \brief Blocking function that resolves a host name or numerical SCION
    /// address.
    Maybe<AddressSet> resolveHost(std::string_view name) const
    {
        return resolveHostImpl(name, boost::asio::use_future).get();
    }

    /// \brief Asynchronous function that resolves a host name or numerical SCION
    /// address.
    template <typename ExecutionContext,
        boost::asio::completion_token_for<void(Maybe<AddressSet>)> CompletionToken>
    auto resolveHostAsync(
        const std::string& name, ExecutionContext& executor, CompletionToken&& token) const
    {
        return resolveHostImpl(name, boost::asio::bind_executor(
            executor.get_executor(), std::forward<CompletionToken>(token)));
    }

    /// \brief Resolves a host name or numerical address with optional port
    /// number. Returns a port of zero if the name didn't contain a port.
    Maybe<std::vector<ScIPEndpoint>> resolveService(std::string_view name)
    {
        auto split = splitHostPort(name);
        if (isError(split)) return propagateError(split);
        auto [host, port] = *split;
        return resolveHost(std::string(host)).transform([port] (const auto& addresses) {
            std::vector<ScIPEndpoint> v;
            v.reserve(addresses.size());
            std::ranges::transform(addresses, std::back_inserter(v), [port] (const auto& addr) {
                return ScIPEndpoint(addr, port);
            });
            return v;
        });
    }
};

} // namespace scion
