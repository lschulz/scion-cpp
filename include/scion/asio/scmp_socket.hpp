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
#include "scion/addr/endpoint.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/asio/addresses.hpp"
#include "scion/extensions/extension.hpp"
#include "scion/posix/underlay.hpp"
#include "scion/socket/packager.hpp"

#include <boost/asio.hpp>


namespace scion {
namespace asio {

class ScmpSocket
{
public:
    using UnderlaySocket = boost::asio::ip::udp::socket;
    using UnderlayEp = typename boost::asio::ip::udp::endpoint;
    using UnderlayAddr = typename EndpointTraits<UnderlayEp>::HostAddr;
    using Endpoint = scion::ScIPEndpoint;
    using Address = scion::ScIPAddress;

protected:
    UnderlaySocket socket;
    ScionPackager packager;

public:
    template <typename Executor>
    explicit ScmpSocket(Executor& ex)
        : socket(ex)
    {}

    /// \brief Bind to a local endpoint.
    /// \warning Wildcard IP addresses are not well supported and should be
    /// avoided. Unspecified ISD-ASN and port are supported.
    std::error_code bind(const Endpoint& ep)
    {
        return bind(ep, 0, 65535);
    }

    /// \brief Bind to a local endpoint. If no port is specified, try to pick
    /// one from the range [`firstPort`, `lastPort`].
    /// \warning Wildcard IP addresses are not well supported and should be
    /// avoided. Unspecified ISD-ASN and port are supported.
    std::error_code bind(
        const Endpoint& ep, std::uint16_t firstPort, std::uint16_t lastPort)
    {
        // Bind underlay socket
        auto underlayEp = generic::toUnderlay<posix::IPEndpoint>(ep.localEp());
        if (isError(underlayEp)) return getError(underlayEp);
        if (underlayEp->data.generic.sa_family == AF_INET6) {
            underlayEp->data.v6.sin6_scope_id = details::byteswapBE(
                ep.address().host().zoneId());
        }
        posix::PosixSocket<posix::IPEndpoint> s;
        auto err = s.bind_range(*underlayEp, firstPort, lastPort);
        if (err) return err;

        // Find local address for SCION layer
        auto local = scion::posix::details::findLocalAddress(s);
        if (isError(local)) return getError(local);

        // Assign bound socket to Asio
        boost::system::error_code ec;
        if (local->host().is4())
            socket.assign(boost::asio::ip::udp::v4(), s.underlaySocket(), ec);
        else
            socket.assign(boost::asio::ip::udp::v6(), s.underlaySocket(), ec);
        if (ec) return ec;
        else s.release();

        // Propagate bound address and port to packet socket
        return packager.setLocalEp(Endpoint(ep.isdAsn(), local->host(), local->port()));
    }

    /// \brief Locally store a default remote address. Receive methods will only
    /// return packets from the "connected" address. Can be called multiple
    /// times to change the remote address or with an unspecified address to
    /// remove again receive from all possible remotes.
    std::error_code connect(const Endpoint& ep)
    {
        return packager.setRemoteEp(ep);
    }

    /// \brief Cancel all asynchronous operations and close the underlay socket.
    void close()
    {
        socket.close();
    }

    /// \brief Cancel all asynchronous operations associated with the socket.
    /// Calls `cancel()` on the underlying ASIO socket.
    std::error_code cancel()
    {
        boost::system::error_code ec;
        socket.cancel(ec);
        return ec;
    }

    /// \brief Determine whether the socket is open.
    bool isOpen() const { return socket.is_open(); }

    /// \brief Get the native handle of the underlay socket.
    UnderlaySocket::native_handle_type underlaySocket()
    {
        return socket.native_handle();
    }

    /// \brief Returns the full address of the socket.
    Endpoint localEp() const { return packager.localEp(); }

    /// \brief Returns the address of the connected remote host.
    Endpoint remoteEp() const { return packager.remoteEp(); }

    /// \brief Set the traffic class of sent packets. Only affects the SCION
    /// header, not the underlay socket.
    void setTrafficClass(std::uint8_t tc) { packager.setTrafficClass(tc); }

    /// \brief Returns the current traffic class.
    std::uint8_t trafficClass() const { return packager.trafficClass(); }

    /// \brief Sets the non-blocking mode of the socket.
    std::error_code setNonblocking(bool nonblocking)
    {
        if (!socket.is_open()) return ErrorCode::InvalidSocket;
        boost::system::error_code ec;
        socket.non_blocking(nonblocking, ec);
        return ec;
    }

    /// \name Synchronous Send
    ///@{

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> sendScmpTo(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(
            headers, &to, path, ext::NoExtensions, hdr::SCMP(message), payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendScmpToExt(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(
            headers, &to, path, std::forward<ExtRange>(extensions), hdr::SCMP(message), payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    ///@}
    /// \name Asynchronous Send
    ///@{

    template <typename Path, typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendScmpToAsync(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        return sendScmpToAsyncImpl(headers, to, path, nextHop, ext::NoExtensions,
            message, payload, token);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendScmpToExtAsync(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        return sendScmpToAsyncImpl(headers, to, path, nextHop, std::forward<ExtRange>(extensions),
            message, payload, token);
    }

    ///@}
    /// \name Synchronous Receive
    ///@{

    Maybe<std::span<std::byte>> recvScmpFromVia(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        hdr::ScmpMessage& message)
    {
        return recvScmpImpl(buf, &from, &path, ulSource,
            ext::NoExtensions, ext::NoExtensions, message);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvScmpFromViaExt(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        hdr::ScmpMessage& message)
    {
        return recvScmpImpl(buf, &from, &path, ulSource,
            std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt), message);
    }

    ///@}
    /// \name Asynchronous Receive
    ///@{

    template <boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
        CompletionToken>
    auto recvScmpFromViaAsync(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        hdr::ScmpMessage& message,
        CompletionToken&& token)
    {
        return recvScmpAsyncImpl(buf, &from, &path, ulSource,
            ext::NoExtensions, ext::NoExtensions, message, token);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt,
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvScmpFromViaExtAsync(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt& hbhExt,
        E2EExt& e2eExt,
        hdr::ScmpMessage& message,
        CompletionToken&& token)
    {
        return recvScmpAsyncImpl(buf, &from, &path, ulSource, hbhExt, e2eExt, message, token);
    }

    ///@}

private:
    template<
        typename Path, ext::extension_range ExtRange, typename Alloc,
        boost::asio::completion_token_for<void(Maybe<std::span<const std::byte>>)>
            CompletionToken>
    auto sendScmpToAsyncImpl(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange& extensions,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload,
        CompletionToken&& token)
    {
        auto initiation = [] (
            boost::asio::completion_handler_for<void(Maybe<std::span<const std::byte>>)>
                auto&& completionHandler,
            UnderlaySocket& socket,
            ScionPackager& packager,
            HeaderCache<Alloc>& headers,
            const Endpoint& to,
            const Path& path,
            const UnderlayEp& nextHop,
            ExtRange& extensions,
            const hdr::ScmpMessage& message,
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

            auto ec = packager.pack(
                headers, &to, path, extensions, hdr::SCMP(message), payload);
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
            std::ref(headers), std::ref(to), std::ref(path), std::ref(nextHop),
            std::ref(extensions), std::ref(message), payload
        );
    }

    template<
        ext::extension_range HbHExt, ext::extension_range E2EExt,
        boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
            CompletionToken>
    auto recvScmpAsyncImpl(
        std::span<std::byte> buf,
        Endpoint* from,
        RawPath* path,
        UnderlayEp& ulSource,
        HbHExt& hbhExt,
        E2EExt& e2eExt,
        hdr::ScmpMessage& message,
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
            hdr::ScmpMessage& message)
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
                hdr::ScmpMessage& message_;
                boost::asio::executor_work_guard<UnderlaySocket::executor_type> ioWork_;
                typename std::decay<decltype(completionHandler)>::type handler_;

                void operator()(const boost::system::error_code& error, std::size_t n)
                {
                    if (error) {
                        ioWork_.reset();
                        handler_(Error(error));
                        return;
                    }

                    std::span<std::byte> payload;
                    auto scmp = [&] (const Address& from, const RawPath& path,
                        const hdr::ScmpMessage& msg, std::span<const std::byte> data)
                    {
                        message_ = msg;
                        payload = std::span<std::byte>{
                            const_cast<std::byte*>(data.data()),
                            data.size()
                        };
                    };

                    auto decoded = packager_.unpack<hdr::UDP>(
                        std::span<const std::byte>(buf_.data(), n),
                        generic::toGenericAddr(ulSource_.address()),
                        std::forward<HbHExt>(hbhExt_), std::forward<E2EExt>(e2eExt_),
                        from_, path_, scmp);
                    if (isError(decoded) && getError(decoded) == ErrorCode::ScmpReceived) {
                        // call the final completion handler
                        ioWork_.reset();
                        handler_(std::span<std::byte>{
                            const_cast<std::byte*>(payload.data()),
                            payload.size()
                        });
                        return;
                    }

                    // do it again
                    socket_.async_receive_from(
                        boost::asio::buffer(buf_), ulSource_, std::move(*this));
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
                    socket, packager, buf, from, path, ulSource, hbhExt, e2eExt, message,
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
            std::ref(hbhExt), std::ref(e2eExt), std::ref(message)
        );
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvScmpImpl(
        std::span<std::byte> buf,
        Endpoint* from,
        RawPath* path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        hdr::ScmpMessage& message)
    {
        std::span<std::byte> payload;
        auto scmp = [&] (const Address& from, const RawPath& path,
            const hdr::ScmpMessage& msg, std::span<const std::byte> data)
        {
            message = msg;
            payload = std::span<std::byte>{
                const_cast<std::byte*>(data.data()),
                data.size()
            };
        };

        while (true) {
            using namespace boost::asio;
            boost::system::error_code ec;
            auto recvd = socket.receive_from(buffer(buf), ulSource, 0, ec);
            if (ec) return Error(ec);
            auto decoded = packager.unpack<hdr::UDP>(
                std::span<const std::byte>(buf.data(), recvd),
                generic::toGenericAddr(ulSource.address()),
                std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt),
                from, path, scmp);
            if (isError(decoded) && getError(decoded) == ErrorCode::ScmpReceived) {
                return payload;
            }
        }
    }

protected:
    Maybe<std::span<const std::byte>> sendUnderlay(
        std::span<const std::byte> headers,
        std::span<const std::byte> payload,
        const UnderlayEp& nextHop)
    {
        using namespace boost::asio;
        boost::system::error_code ec;
        std::array<const_buffer, 2> buffers = {
            buffer(headers), buffer(payload),
        };
        auto sent = socket.send_to(buffers, nextHop, 0, ec);
        if (ec) return Error(ec);
        auto n = (std::int_fast32_t)sent - (std::int_fast32_t)headers.size();
        if (n < 0) return Error(ErrorCode::PacketTooBig);
        return payload.subspan(0, n);
    }
};

} // namespace asio
} // namespace scion
