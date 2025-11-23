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
#include "scion/socket/flags.hpp"
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
    /// \details See bind(const Endpoint&, std::uint16_t, std::uint16_t, const
    /// UnderlayAddr*) for more details.
    std::error_code bind(const Endpoint& ep)
    {
        return bind(ep, 0, 65535);
    }

    /// \brief Bind to a local endpoint. If no port is specified, try to pick
    /// one from the range [`firstPort`, `lastPort`].
    /// \param ep SCION endpoint to bind to. This address is used as the source
    /// address in the SCION address header. Wildcard IP addresses (0.0.0.0,
    /// ::0) should be avoided as the implementation will have to guess an
    /// appropriate IP address to put in the SCION header. Unspecified ISD-ASN
    /// (0-0) and port (0) are supported. If the underlay socket should be bound
    /// to a different interface (including *all* interfaces) than determined by
    /// the IP specified here, use the `underlay` paramater.
    /// \param underlay Optional bind address for the underlay UDP socket. By
    /// default this is `ep.host()`. The port is determined from `ep` or if
    /// unspecified selected automatically from the range [`firstPort`,
    /// `lastPort`]. Wildcard addresses are accepted.
    std::error_code bind(
        const Endpoint& ep, std::uint16_t firstPort, std::uint16_t lastPort,
        const posix::IPAddress* underlay = nullptr)
    {
        // Bind underlay socket
        posix::PosixSocket<posix::IPEndpoint> s;
        if (underlay) {
            auto underlayEp = EndpointTraits<posix::IPEndpoint>::fromHostPort(*underlay, ep.port());
            auto err = s.bind_range(underlayEp, firstPort, lastPort);
            if (err) return err;
        } else {
            auto underlayEp = generic::toUnderlay<posix::IPEndpoint>(ep.localEp());
            if (isError(underlayEp)) return getError(underlayEp);
            if (underlayEp->data.generic.sa_family == AF_INET6) {
                underlayEp->data.v6.sin6_scope_id = details::byteswapBE(
                    ep.address().host().zoneId());
            }
            auto err = s.bind_range(*underlayEp, firstPort, lastPort);
            if (err) return err;
        }

        // Find local address for SCION layer
        generic::IPAddress addr = ep.host();
        std::uint16_t port = ep.port();
        if (addr.isUnspecified() || port == 0) {
            auto local = posix::details::findLocalAddress(s);
            if (isError(local)) return getError(local);
            if (addr.isUnspecified())
                addr = local->host();
            if (port == 0)
                port = local->port();
        }

        // Assign bound socket to Asio
        boost::system::error_code ec;
        if (addr.is4())
            socket.assign(boost::asio::ip::udp::v4(), s.underlaySocket(), ec);
        else
            socket.assign(boost::asio::ip::udp::v6(), s.underlaySocket(), ec);
        if (ec) return ec;
        else s.release();

        // Propagate bound address and port to packet socket
        return packager.setLocalEp(Endpoint(ep.isdAsn(), addr.unmap4in6(), port));
    }

    /// \brief Set or change the local address without actually binding the
    /// underlay socket. The local address is used as source address for sent
    /// packets and to filter received packets.
    ///
    /// \copydetails ScionPackager::setLocalEp()
    ///
    /// \warning This is a low-level operation, most clients should simply call
    /// bind.
    std::error_code setLocalEp(const Endpoint& ep)
    {
        if (ep.host().is4in6()) {
            return packager.setLocalEp(Endpoint(ep.isdAsn(), ep.host().unmap4in6(), ep.port()));
        } else {
            return packager.setLocalEp(ep);
        }
    }

    /// \brief Set the host address and port after SNAT to facilitate NAT
    /// traversal. NAT traversal can be disabled by setting this address to
    /// the same IP and port as returned by localEp() again.
    void setMappedIpAndPort(const Endpoint::LocalEp& mapped)
    {
        packager.setMappedIpAndPort(mapped);
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

    /// \brief Returns the local address after SNAT. Differs from localEp() if
    /// and only if NAT traversal is active.
    Endpoint mappedEp() const { return packager.localEp(); }

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

    /// \name Header Size Measurement
    ///@{

    template <typename Path>
    Maybe<std::size_t> measureScmpTo(
        const Endpoint& to,
        const Path& path,
        const hdr::ScmpMessage& message)
    {
        return packager.measure(&to, path, ext::NoExtensions, hdr::SCMP(message));
    }

    template <typename Path, ext::extension_range ExtRange>
    Maybe<std::size_t> measureScmpToExt(
        const Endpoint& to,
        const Path& path,
        ExtRange&& extensions,
        const hdr::ScmpMessage& message)
    {
        return packager.measure(&to, path, std::forward<ExtRange>(extensions), hdr::SCMP(message));
    }

    ///@}
    /// \name Synchronous Send
    ///@{

    /// \brief Send a STUN binding request to the given router and prepare the
    /// recv* methods to expect a STUN response.
    std::error_code requestStunMapping(const UnderlayEp& router)
    {
        std::array<std::byte, 20> buffer;
        std::span<std::byte> span(buffer.data(), buffer.size());
        auto server = generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(router));
        auto ec = packager.createStunRequest(span, server);
        if (ec) return ec;
        auto res = sendUnderlay(span, std::span<std::byte>(), router);
        if (isError(res)) return res.error();
        return ErrorCode::Ok;
    }

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> sendScmpTo(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~SMSG_NO_FLAGS) return Error(ErrorCode::InvalidArgument);
        auto ec = packager.pack(
            headers, &to, path, ext::NoExtensions, hdr::SCMP(message), payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendScmpToExt(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~SMSG_NO_FLAGS) return Error(ErrorCode::InvalidArgument);
        auto ec = packager.pack(
            headers, &to, path, std::forward<ExtRange>(extensions), hdr::SCMP(message), payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    ///@}
    /// \name Asynchronous Send
    ///@{

    /// \brief Send a STUN binding request to the given router and prepare the
    /// recv* methods to expect a STUN response.
    template <boost::asio::completion_token_for<void(std::error_code)> CompletionToken>
    auto requestStunMappingAsync(const UnderlayEp& router, CompletionToken&& token)
    {
        auto initiation = [] (
            boost::asio::completion_handler_for<void(std::error_code)> auto&& completionHandler,
            UnderlaySocket& socket,
            ScionPackager& packager,
            const UnderlayEp& router)
        {
            struct intermediate_completion_handler
            {
                UnderlaySocket& socket_;
                std::unique_ptr<std::array<std::byte, 20>> buf_;
                typename std::decay<decltype(completionHandler)>::type handler_;

                void operator()(const boost::system::error_code& error, std::size_t sent)
                {
                    if (error) handler_(error);
                    handler_(ErrorCode::Ok);
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

            auto buf = std::make_unique<std::array<std::byte, 20>>();
            auto ec = packager.createStunRequest(
                std::span<std::byte, 20>(buf->data(), buf->size()),
                generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(router)));
            if (ec) {
                auto executor = boost::asio::get_associated_executor(
                    completionHandler, socket.get_executor());
                boost::asio::post(
                    boost::asio::bind_executor(executor,
                        std::bind(std::forward<decltype(completionHandler)>(completionHandler),
                            ec)));
            } else {
                auto asioBuffer = boost::asio::buffer(*buf);
                socket.async_send_to(asioBuffer, router,
                    intermediate_completion_handler{
                        socket, std::move(buf),
                        std::forward<decltype(completionHandler)>(completionHandler)
                    }
                );
            }
        };

        return boost::asio::async_initiate<
            CompletionToken, void(std::error_code)>
        (
            initiation, token,
            std::ref(socket), std::ref(packager), std::ref(router)
        );
    }

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

    /// \brief Receive packets until a STUN response matching the last request
    /// made with requestStunMapping() or requestStunMappingAsync() is found.
    std::error_code recvStunResponse(MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~SMSG_NO_FLAGS) return ErrorCode::InvalidArgument;
        std::array<std::byte, 128> buf;
        UnderlayEp ulSource;
        while (true) {
            using namespace boost::asio;
            boost::system::error_code ec;
            auto n = socket.receive_from(buffer(buf), ulSource, flags, ec);
            if (ec) return ec;
            auto server = generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(ulSource));
            ec = packager.unpackStun(std::span<std::byte>(buf.data(), n), server);
            if (ec == ErrorCode::StunReceived) return ec;
            else if (ec != ErrorCode::Pending) return ec;
        }
    }

    Maybe<std::span<std::byte>> recvScmpFromVia(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        hdr::ScmpMessage& message,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~(SMSG_PEEK | SMSG_RECV_SCMP | SMSG_RECV_STUN))
            return Error(ErrorCode::InvalidArgument);
        return recvScmpImpl(buf, &from, &path, ulSource,
            ext::NoExtensions, ext::NoExtensions, message, flags);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvScmpFromViaExt(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        hdr::ScmpMessage& message,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~(SMSG_PEEK | SMSG_RECV_SCMP | SMSG_RECV_STUN))
            return Error(ErrorCode::InvalidArgument);
        return recvScmpImpl(buf, &from, &path, ulSource,
            std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt), message, flags);
    }

    ///@}
    /// \name Asynchronous Receive
    ///@{

    /// \brief Receive packets until a STUN response matchin the last request
    /// made with requestStunMapping() is found.
    template <boost::asio::completion_token_for<void(std::error_code)> CompletionToken>
    auto recvStunResponseAsync(CompletionToken&& token)
    {
        auto initiation = [] (
            boost::asio::completion_handler_for<void(std::error_code)> auto&& completionHandler,
            UnderlaySocket& socket,
            ScionPackager& packager)
        {
            struct intermediate_completion_handler
            {
                UnderlaySocket& socket_;
                ScionPackager& packager_;
                std::unique_ptr<std::array<std::byte, 128>> buf_;
                std::unique_ptr<UnderlayEp> ulSource_;
                boost::asio::executor_work_guard<UnderlaySocket::executor_type> ioWork_;
                typename std::decay<decltype(completionHandler)>::type handler_;

                void operator()(const boost::system::error_code& error, std::size_t n)
                {
                    if (error) {
                        ioWork_.reset();
                        handler_(error);
                        return;
                    }

                    auto ec = packager_.unpackStun(*buf_,
                        generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(*ulSource_)));
                    if (ec == ErrorCode::StunReceived || ec != ErrorCode::Pending) {
                        // call the final completion handler
                        ioWork_.reset();
                        handler_(ec);
                        return;
                    } else {
                        // do it again
                        socket_.async_receive_from(
                            boost::asio::buffer(*buf_), *ulSource_, std::move(*this));
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

            intermediate_completion_handler intermediate{
                socket, packager,
                std::make_unique<std::array<std::byte, 128>>(),
                std::make_unique<UnderlayEp>(),
                boost::asio::make_work_guard(socket.get_executor()),
                std::forward<decltype(completionHandler)>(completionHandler)
            };
            socket.async_receive_from(
                boost::asio::buffer(*intermediate.buf_), *intermediate.ulSource_,
                std::move(intermediate)
            );
        };

        return boost::asio::async_initiate<CompletionToken, void(std::error_code)>
        (
            initiation, token, std::ref(socket), std::ref(packager)
        );
    }

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
            ext::NoExtensions, ext::NoExtensions, message, SMSG_NO_FLAGS, token);
    }

    template <boost::asio::completion_token_for<void(Maybe<std::span<std::byte>>)>
        CompletionToken>
    auto recvScmpFromViaAsync(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        hdr::ScmpMessage& message,
        MsgFlags flags,
        CompletionToken&& token)
    {
        if (flags & ~(SMSG_RECV_SCMP | SMSG_RECV_STUN)) return Error(ErrorCode::InvalidArgument);
        return recvScmpAsyncImpl(buf, &from, &path, ulSource,
            ext::NoExtensions, ext::NoExtensions, message, flags, token);
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
        return recvScmpAsyncImpl(buf, &from, &path, ulSource,
            hbhExt, e2eExt, message, SMSG_NO_FLAGS, token);
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
        MsgFlags flags,
        CompletionToken&& token)
    {
        if (flags & ~(SMSG_RECV_SCMP | SMSG_RECV_STUN)) return Error(ErrorCode::InvalidArgument);
        return recvScmpAsyncImpl(buf, &from, &path, ulSource,
            hbhExt, e2eExt, message, flags, token);
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
        MsgFlags flags,
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
            hdr::ScmpMessage& message,
            MsgFlags flags)
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
                MsgFlags flags_;
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
                    if (isError(decoded)) {
                        if (getError(decoded) == ErrorCode::ScmpReceived) {
                            // call the final completion handler
                            ioWork_.reset();
                            handler_(std::span<std::byte>{
                                const_cast<std::byte*>(payload.data()),
                                payload.size()
                            });
                            return;
                        } else if (getError(decoded) == ErrorCode::ScmpReceived) {
                            if (flags_ & SMSG_RECV_STUN) {
                                ioWork_.reset();
                                handler_(propagateError(decoded));
                                return;
                            }
                        }
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

            socket.async_receive_from(boost::asio::buffer(buf), ulSource, flags & ~SMSG_SCION_ALL,
                intermediate_completion_handler{
                    socket, packager, buf, from, path, ulSource, hbhExt, e2eExt, message, flags,
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
            std::ref(hbhExt), std::ref(e2eExt), std::ref(message), flags
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
        hdr::ScmpMessage& message,
        MsgFlags flags = SMSG_NO_FLAGS)
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
            auto recvd = socket.receive_from(buffer(buf), ulSource, flags & ~SMSG_SCION_ALL, ec);
            if (ec) return Error(ec);
            auto decoded = packager.unpack<hdr::UDP>(
                std::span<const std::byte>(buf.data(), recvd),
                generic::toGenericAddr(ulSource.address()),
                std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt),
                from, path, scmp);
            if (isError(decoded)) {
                if (getError(decoded) == ErrorCode::ScmpReceived) {
                    return payload;
                } else if (getError(decoded) == ErrorCode::StunReceived) {
                    if (flags & SMSG_RECV_STUN) return propagateError(decoded);
                }
            } else if (flags & SMSG_PEEK) {
                // discard the peeked packet from the receive queue
                (void)socket.receive_from(buffer(buf), ulSource,
                    flags & ~(SMSG_PEEK | SMSG_SCION_ALL));
            }
        }
    }

protected:
    Maybe<std::span<const std::byte>> sendUnderlay(
        std::span<const std::byte> headers,
        std::span<const std::byte> payload,
        const UnderlayEp& nextHop,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        using namespace boost::asio;
        boost::system::error_code ec;
        std::array<const_buffer, 2> buffers = {
            buffer(headers), buffer(payload),
        };
        auto sent = socket.send_to(buffers, nextHop, flags, ec);
        if (ec) return Error(ec);
        auto n = (std::int_fast32_t)sent - (std::int_fast32_t)headers.size();
        if (n < 0) return Error(ErrorCode::PacketTooBig);
        return payload.subspan(0, n);
    }
};

} // namespace asio
} // namespace scion
