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

#include "scion/asio/scmp_socket.hpp"
#include "scion/scmp/handler.hpp"


namespace scion {
namespace asio {

/// \brief A UDP SCION socket supporting synchronous and asynchronous operations
/// via Asio.
class UdpSocket : public ScmpSocket
{
protected:
    ScmpHandler* scmpHandler;

public:
    template <typename Executor>
    explicit UdpSocket(Executor& ex)
        : ScmpSocket(ex)
    {}

    void setNextScmpHandler(ScmpHandler* handler) { scmpHandler = handler; }
    ScmpHandler* nextScmpHandler() const { return scmpHandler; }

    /// \name Synchronous Send
    ///@{

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> send(
        HeaderCache<Alloc>& headers,
        const Path& path,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(headers, nullptr, path, ext::NoExtensions, hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendExt(
        HeaderCache<Alloc>& headers,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(headers, nullptr, path,
            std::forward<ExtRange>(extensions), hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> sendTo(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(headers, &to, path, ext::NoExtensions, hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendToExt(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(headers, &to, path,
            std::forward<ExtRange>(extensions), hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Alloc>
    Maybe<std::span<const std::byte>> sendCached(
        HeaderCache<Alloc>& headers,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload)
    {
        hdr::UDP udp;
        udp.sport = packager.localEp().port();
        udp.dport = packager.remoteEp().port();
        auto ec = packager.pack(headers, udp, payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Alloc>
    Maybe<std::span<const std::byte>> sendToCached(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload)
    {
        hdr::UDP udp;
        udp.sport = packager.localEp().port();
        udp.dport = to.port();
        auto ec = packager.pack(headers, udp, payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    ///@}
    /// \name Asynchronous Send
    ///@{

    template <
        typename Path, typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendAsync(
        HeaderCache<Alloc>& headers,
        const Path& path,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        return sendAsyncImpl(headers, nullptr, path, nextHop, ext::NoExtensions, payload,
            std::forward<CompletionToken>(token));
    }

    template <
        typename Path, ext::extension_range ExtRange, typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendExtAsync(
        HeaderCache<Alloc>& headers,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        return sendAsyncImpl(headers, nullptr, path, nextHop,
            std::forward<ExtRange>(extensions), payload,
            std::forward<CompletionToken>(token));
    }

    template <
        typename Path, typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendToAsync(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        return sendAsyncImpl(headers, &to, path, nextHop, ext::NoExtensions, payload,
            std::forward<CompletionToken>(token));
    }

    template <
        typename Path, ext::extension_range ExtRange, typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendToExtAsync(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        return sendAsyncImpl(headers, &to, path, nextHop,
            std::forward<ExtRange>(extensions), payload,
            std::forward<CompletionToken>(token));
    }

    template <
        typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendCachedAsync(
        HeaderCache<Alloc>& headers,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        return sendCachedAsyncImpl(headers, nullptr, nextHop, payload,
            std::forward<CompletionToken>(token));
    }

    template <
        typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendToCachedAsync(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        return sendCachedAsyncImpl(headers, &to, nextHop, payload,
            std::forward<CompletionToken>(token));
    }

    ///@}
    /// \name Synchronous Receive
    ///@{

    Maybe<std::span<std::byte>> recv(std::span<std::byte> buf)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, nullptr, nullptr, ulSource, ext::NoExtensions, ext::NoExtensions);
    }

    template<ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvExt(
        std::span<std::byte> buf,
        HbHExt& hbhExt,
        E2EExt& e2eExt)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, nullptr, nullptr, ulSource, hbhExt, e2eExt);
    }

    Maybe<std::span<std::byte>> recvFrom(
        std::span<std::byte> buf,
        Endpoint& from)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, &from, nullptr, ulSource, ext::NoExtensions, ext::NoExtensions);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvFromExt(
        std::span<std::byte> buf,
        Endpoint& from,
        HbHExt& hbhExt,
        E2EExt& e2eExt)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, &from, nullptr, ulSource, hbhExt, e2eExt);
    }

    auto recvFromVia(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource)
    {
        return recvImpl(buf, &from, &path, ulSource, ext::NoExtensions, ext::NoExtensions);
    }

    template<ext::extension_range HbHExt, ext::extension_range E2EExt>
    auto recvFromViaExt(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt& hbhExt,
        E2EExt& e2eExt)
    {
        return recvImpl(buf, &from, &path, ulSource, hbhExt, e2eExt);
    }

    ///@}
    /// \name Asynchronous Receive
    ///@{

    template<
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvAsync(
        std::span<std::byte> buf,
        UnderlayEp& ulSource,
        CompletionToken&& token)
    {
        return recvAsyncImpl(buf, nullptr, nullptr, ulSource, ext::NoExtensions, ext::NoExtensions,
            std::forward<CompletionToken>(token));
    }

    template<
        ext::extension_range HbHExt, ext::extension_range E2EExt,
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvExtAsync(
        std::span<std::byte> buf,
        UnderlayEp& ulSource,
        HbHExt& hbhExt,
        E2EExt& e2eExt,
        CompletionToken&& token)
    {
        return recvAsyncImpl(buf, nullptr, nullptr, ulSource, hbhExt, e2eExt,
            std::forward<CompletionToken>(token));
    }

    template<
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvFromAsync(
        std::span<std::byte> buf,
        Endpoint& from,
        UnderlayEp& ulSource,
        CompletionToken&& token)
    {
        return recvAsyncImpl(buf, &from, nullptr, ulSource, ext::NoExtensions, ext::NoExtensions,
            std::forward<CompletionToken>(token));
    }

    template<
        ext::extension_range HbHExt, ext::extension_range E2EExt,
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvFromExtAsync(
        std::span<std::byte> buf,
        Endpoint& from,
        UnderlayEp& ulSource,
        HbHExt& hbhExt,
        E2EExt& e2eExt,
        CompletionToken&& token)
    {
        return recvAsyncImpl(buf, &from, nullptr, ulSource, hbhExt, e2eExt,
            std::forward<CompletionToken>(token));
    }

    template<
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvFromViaAsync(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        CompletionToken&& token)
    {
        return recvAsyncImpl(buf, &from, &path, ulSource, ext::NoExtensions, ext::NoExtensions,
            std::forward<CompletionToken>(token));
    }

    template<
        ext::extension_range HbHExt, ext::extension_range E2EExt,
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvFromViaExtAsync(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt& hbhExt,
        E2EExt& e2eExt,
        CompletionToken&& token)
    {
        return recvAsyncImpl(buf, &from, &path, ulSource, hbhExt, e2eExt,
            std::forward<CompletionToken>(token));
    }

    ///@}

private:
    template<
        typename Path, ext::extension_range ExtRange, typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendAsyncImpl(
        HeaderCache<Alloc>& headers,
        const Endpoint* to,
        const Path& path,
        const UnderlayEp& nextHop,
        const ExtRange& extensions,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        auto initiation = [] (
            boost::asio::completion_handler_for<void(Maybe<std::span<const std::byte>>)>
                auto&& completionHandler,
            UnderlaySocket& socket,
            ScionPackager& packager,
            HeaderCache<Alloc>& headers,
            const Endpoint* to,
            const Path& path,
            const UnderlayEp& nextHop,
            const ExtRange& extensions,
            std::span<const std::byte> payload)
        {
            struct intermediate_completion_handler
            {
                UnderlaySocket& socket_;
                std::span<const std::byte> headers;
                std::span<const std::byte> payload_;
                typename std::decay<decltype(completionHandler)>::type handler_;

                void operator()(const boost::system::error_code& error, std::size_t sent)
                {
                    Maybe<std::span<const std::byte>> result;
                    auto n = (std::int_fast32_t)sent - (std::int_fast32_t)headers.size();
                    if (error) result = Error(error);
                    else if (n < 0) result = Error(ErrorCode::PacketTooBig);
                    else result = payload_.subspan(0, n);
                    handler_(result);
                }

                using executor_type = boost::asio::associated_executor_t<
                    typename std::decay<decltype(completionHandler)>::type,
                    UnderlaySocket::executor_type>;
                executor_type get_executor() const noexcept
                {
                    return boost::asio::get_associated_executor(
                        handler_, socket_.get_executor());
                }

                using allocator_type = boost::asio::associated_allocator_t<
                    typename std::decay<decltype(completionHandler)>::type,
                    std::allocator<void>>;
                allocator_type get_allocator() const noexcept
                {
                    return boost::asio::get_associated_allocator(
                        handler_, std::allocator<void>{});
                }
            };

            auto ec = packager.pack(headers, to, path, extensions, hdr::UDP{}, payload);
            if (ec) {
                auto executor = boost::asio::get_associated_executor(
                    completionHandler, socket.get_executor());
                boost::asio::post(
                    boost::asio::bind_executor(executor,
                        std::bind(std::forward<decltype(completionHandler)>(completionHandler),
                            Error(ec))));
            } else {
                std::array<boost::asio::const_buffer, 2> buffers = {
                    boost::asio::buffer(headers.get()), boost::asio::buffer(payload),
                };
                socket.async_send_to(buffers, nextHop,
                    intermediate_completion_handler{
                        socket, headers.get(), payload,
                        std::forward<decltype(completionHandler)>(completionHandler)
                    }
                );
            }
        };

        return boost::asio::async_initiate<
            CompletionToken, void(Maybe<std::span<const std::byte>>)>
        (
            initiation, token,
            std::ref(socket), std::ref(packager),
            std::ref(headers), to, std::ref(path), std::ref(nextHop),
            std::ref(extensions), payload
        );
    }

    template<
        typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendCachedAsyncImpl(
        HeaderCache<Alloc>& headers,
        const Endpoint* to,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        auto initiation = [] (
            boost::asio::completion_handler_for<void(Maybe<std::span<const std::byte>>)>
                auto&& completionHandler,
            UnderlaySocket& socket,
            ScionPackager& packager,
            HeaderCache<Alloc>& headers,
            const Endpoint* to,
            const UnderlayEp& nextHop,
            std::span<const std::byte> payload)
        {
            struct intermediate_completion_handler
            {
                UnderlaySocket& socket_;
                std::span<const std::byte> headers;
                std::span<const std::byte> payload_;
                typename std::decay<decltype(completionHandler)>::type handler_;

                void operator()(const boost::system::error_code& error, std::size_t sent)
                {
                    Maybe<std::span<const std::byte>> result;
                    auto n = (std::int_fast32_t)sent - (std::int_fast32_t)headers.size();
                    if (error) result = Error(error);
                    else if (n < 0) result = Error(ErrorCode::PacketTooBig);
                    else result = payload_.subspan(0, n);
                    handler_(result);
                }

                using executor_type = boost::asio::associated_executor_t<
                    typename std::decay<decltype(completionHandler)>::type,
                    UnderlaySocket::executor_type>;
                executor_type get_executor() const noexcept
                {
                    return boost::asio::get_associated_executor(
                        handler_, socket_.get_executor());
                }

                using allocator_type = boost::asio::associated_allocator_t<
                    typename std::decay<decltype(completionHandler)>::type,
                    std::allocator<void>>;
                allocator_type get_allocator() const noexcept
                {
                    return boost::asio::get_associated_allocator(
                        handler_, std::allocator<void>{});
                }
            };

            hdr::UDP udp;
            udp.sport = packager.localEp().port();
            if (to) udp.dport = to->port();
            else udp.dport = packager.remoteEp().port();
            auto ec = packager.pack(headers, udp, payload);
            if (ec) {
                auto executor = boost::asio::get_associated_executor(
                    completionHandler, socket.get_executor());
                boost::asio::post(
                    boost::asio::bind_executor(executor,
                        std::bind(std::forward<decltype(completionHandler)>(completionHandler),
                            Error(ec))));
            } else {
                std::array<boost::asio::const_buffer, 2> buffers = {
                    boost::asio::buffer(headers.get()), boost::asio::buffer(payload),
                };
                socket.async_send_to(buffers, nextHop,
                    intermediate_completion_handler{
                        socket, headers.get(), payload,
                        std::forward<decltype(completionHandler)>(completionHandler)
                    }
                );
            }
        };

        return boost::asio::async_initiate<
            CompletionToken, void(Maybe<std::span<const std::byte>>)>
        (
            initiation, token,
            std::ref(socket), std::ref(packager),
            std::ref(headers), to, std::ref(nextHop), payload
        );
    }

    template<
        ext::extension_range HbHExt, ext::extension_range E2EExt,
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvAsyncImpl(
        std::span<std::byte> buf,
        Endpoint* from,
        RawPath* path,
        UnderlayEp& ulSource,
        HbHExt& hbhExt,
        E2EExt& e2eExt,
        CompletionToken&& token)
    {
        auto initiation = [] (
            boost::asio::completion_handler_for<void(Maybe<std::span<std::byte>>)>
                auto&& completionHandler,
            UnderlaySocket& socket,
            ScionPackager& packager,
            std::span<std::byte> buf,
            Endpoint* from,
            RawPath* path,
            UnderlayEp& ulSource,
            HbHExt& hbhExt,
            E2EExt& e2eExt,
            ScmpHandler* scmpHandler)
        {
            struct intermediate_completion_handler
            {
                UnderlaySocket& socket_;
                ScionPackager& packager_;
                std::span<std::byte> buf_;
                Endpoint* from_;
                RawPath* path_;
                UnderlayEp& ulSource_;
                HbHExt& hbhExt_;
                E2EExt& e2eExt_;
                ScmpHandler* scmpHandler_;
                boost::asio::executor_work_guard<UnderlaySocket::executor_type> ioWork_;
                typename std::decay<decltype(completionHandler)>::type handler_;

                void operator()(const boost::system::error_code& error, std::size_t n)
                {
                    if (error) {
                        ioWork_.reset();
                        handler_(Error(error));
                        return;
                    }
                    auto scmpCallback = [this] (
                        const scion::ScIPAddress& from,
                        const RawPath& path,
                        const hdr::ScmpMessage& msg,
                        std::span<const std::byte> payload)
                    {
                        if (scmpHandler_) scmpHandler_->handleScmp(from, path, msg, payload);
                    };
                    auto payload = packager_.template unpack<hdr::UDP>(
                        buf_.subspan(0, n),
                        generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(ulSource_)),
                        hbhExt_, e2eExt_, from_, path_, scmpCallback);
                    if (isError(payload)) {
                        if (getError(payload) != ErrorCode::ScmpReceived) {
                            SCION_DEBUG_PRINT((std::format(
                                "Received invalid packet from {}: {}\n",
                                ulSource_, fmtError(getError(payload))
                            )));
                        }
                        socket_.async_receive_from(
                            boost::asio::buffer(buf_), ulSource_, std::move(*this));
                        return; // do it again
                    } else {
                        // call the final completion handler
                        ioWork_.reset();
                        handler_(std::span<std::byte>{
                            const_cast<std::byte*>(payload->data()),
                            payload->size()
                        });
                    }
                }

                using executor_type = boost::asio::associated_executor_t<
                    typename std::decay<decltype(completionHandler)>::type,
                    UnderlaySocket::executor_type>;
                executor_type get_executor() const noexcept
                {
                    return boost::asio::get_associated_executor(
                        handler_, socket_.get_executor());
                }

                using allocator_type = boost::asio::associated_allocator_t<
                    typename std::decay<decltype(completionHandler)>::type,
                    std::allocator<void>>;
                allocator_type get_allocator() const noexcept
                {
                    return boost::asio::get_associated_allocator(
                        handler_, std::allocator<void>{});
                }
            };

            socket.async_receive_from(boost::asio::buffer(buf), ulSource,
                intermediate_completion_handler{
                    socket, packager, buf, from, path, ulSource, hbhExt, e2eExt, scmpHandler,
                    boost::asio::make_work_guard(socket.get_executor()),
                    std::forward<decltype(completionHandler)>(completionHandler)
                }
            );
        };

        return boost::asio::async_initiate<
            CompletionToken, void(Maybe<std::span<std::byte>>)>
        (
            initiation, token,
            std::ref(socket), std::ref(packager), buf, from, path, std::ref(ulSource),
            std::ref(hbhExt), std::ref(e2eExt), scmpHandler
        );
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvImpl(
        std::span<std::byte> buf,
        Endpoint* from,
        RawPath* path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt)
    {
        auto scmpCallback = [this] (
            const scion::ScIPAddress& from,
            const RawPath& path,
            const hdr::ScmpMessage& msg,
            std::span<const std::byte> payload)
        {
            if (scmpHandler) scmpHandler->handleScmp(from, path, msg, payload);
        };
        while (true) {
            using namespace boost::asio;
            boost::system::error_code ec;
            auto recvd = socket.receive_from(buffer(buf), ulSource, 0, ec);
            if (ec) return Error(ec);
            auto payload = packager.template unpack<hdr::UDP>(
                std::span<const std::byte>(buf.data(), recvd),
                generic::toGenericAddr(ulSource.address()),
                std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt),
                from, path, scmpCallback);
            if (payload.has_value()) {
                return std::span<std::byte>{
                    const_cast<std::byte*>(payload->data()),
                    payload->size()
                };
            }
            if (getError(payload) != ErrorCode::ScmpReceived) {
                SCION_DEBUG_PRINT((std::format(
                    "Received invalid packet from {}: {}\n", ulSource, fmtError(getError(payload)))));
            }
        }
    }
};

} // namespace asio
} // namespace scion
