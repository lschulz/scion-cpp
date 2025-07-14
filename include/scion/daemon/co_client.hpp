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

#include "scion/daemon/client.hpp"

#include <agrpc/client_rpc.hpp>
#include <boost/asio.hpp>


namespace scion {
namespace daemon {

/// \brief Coroutine-based SCION daemon client.
class CoGrpcDaemonClient : public GrpcDaemonClient
{
protected:
    agrpc::GrpcContext& grpcCtx;

public:
    /// \brief Initialize the client.
    /// \param grpcCtx Asynchronous execution context. Must remain valid for the
    ///     entire lifetime of the client.
    /// \param target Address of the SCION daemon to connect to.
    CoGrpcDaemonClient(agrpc::GrpcContext& grpcCtx, const grpc::string& target)
        : GrpcDaemonClient(target), grpcCtx(grpcCtx)
    {}

    /// \copydoc GrpcDaemonClient::rpcPaths
    template <std::output_iterator<PathPtr> OutIter>
    auto rpcPathsAsync(IsdAsn src, IsdAsn dst, PathReqFlagSet flags, OutIter out)
        -> boost::asio::awaitable<std::error_code>
    {
        using boost::asio::use_awaitable;
        using rpc = agrpc::ClientRPC<&proto::daemon::v1::DaemonService::Stub::PrepareAsyncPaths>;

        grpc::ClientContext ctx;
        rpc::Request request;
        request.set_source_isd_as(src);
        request.set_destination_isd_as(dst);
        request.set_refresh(flags[PathReqFlags::Refresh]);
        request.set_hidden(flags[PathReqFlags::Hidden]);

        rpc::Response response;
        auto status = co_await rpc::request(grpcCtx, stub, ctx, request, response, use_awaitable);
        if (!status.ok()) co_return Error(status.error_code());

        for (const auto& path : response.paths()) {
            auto cooked = details::pathFromProtobuf(src, dst, path, flags);
            if (cooked) *out++ = std::move(*cooked);
        }
        co_return status.error_code();
    }

    /// \copydoc GrpcDaemonClient::rpcAsInfo
    auto rpcAsInfoAsync(IsdAsn isdAsn) -> boost::asio::awaitable<Maybe<AsInfo>>
    {
        using boost::asio::use_awaitable;
        using rpc = agrpc::ClientRPC<&proto::daemon::v1::DaemonService::Stub::PrepareAsyncAS>;

        grpc::ClientContext ctx;
        rpc::Request request;
        request.set_isd_as(isdAsn);

        rpc::Response response;
        auto status = co_await rpc::request(grpcCtx, stub, ctx, request, response, use_awaitable);
        if (!status.ok()) co_return Error(status.error_code());

        co_return AsInfo {
            IsdAsn(response.isd_as()),
            response.core(),
            response.mtu(),
        };
    }

    /// \copydoc GrpcDaemonClient::rpcServices
    template <std::output_iterator<std::pair<std::string, std::string>> OutIter>
    auto rpcServicesAsync(OutIter out) -> boost::asio::awaitable<std::error_code>
    {
        using boost::asio::use_awaitable;
        using rpc = agrpc::ClientRPC<&proto::daemon::v1::DaemonService::Stub::PrepareAsyncServices>;

        grpc::ClientContext ctx;
        rpc::Request request;
        rpc::Response response;

        auto status = co_await rpc::request(grpcCtx, stub, ctx, request, response, use_awaitable);
        if (!status.ok()) co_return status.error_code();

        for (const auto& elem : response.services()) {
            for (const auto& service : elem.second.services()) {
                *out++ = std::make_pair(elem.first, service.uri());
            }
        }
        co_return status.error_code();
    }

    /// \copydoc GrpcDaemonClient::rpcPortRange
    auto rpcPortRangeAsync() -> boost::asio::awaitable<Maybe<PortRange>>
    {
        using boost::asio::use_awaitable;
        using rpc = agrpc::ClientRPC<
            &proto::daemon::v1::DaemonService::Stub::PrepareAsyncPortRange>;

        grpc::ClientContext ctx;
        rpc::Request request;
        rpc::Response response;

        auto status = co_await rpc::request(grpcCtx, stub, ctx, request, response, use_awaitable);
        if (!status.ok()) co_return Error(status.error_code());

        co_return std::make_pair(response.dispatched_port_start(), response.dispatched_port_end());
    }

    /// \copydoc GrpcDaemonClient::rpcDRKeyHostAS
    auto rpcDRKeyHostAS(const DRKeyHostASRequest& hostASReq)
        -> boost::asio::awaitable<Maybe<drkey::Key>>
    {
        using boost::asio::use_awaitable;
        using rpc = agrpc::ClientRPC<
            &proto::daemon::v1::DaemonService::Stub::PrepareAsyncDRKeyHostAS>;
        using namespace scion::details;

        grpc::ClientContext ctx;
        rpc::Request req;
        req.mutable_val_time()->set_seconds((std::uint32_t)(timepointSeconds(hostASReq.valTime)));
        req.mutable_val_time()->set_nanos((std::uint32_t)(timepointNanos(hostASReq.valTime)));
        req.set_protocol_id(static_cast<proto::drkey::v1::Protocol>(hostASReq.protocol));
        req.set_src_ia(hostASReq.srcIA);
        req.set_dst_ia(hostASReq.dstIA);
        req.set_src_host(hostASReq.srcHost);

        rpc::Response resp;
        auto status = co_await rpc::request(grpcCtx, stub, ctx, req, resp, use_awaitable);
        if (!status.ok()) co_return Error(status.error_code());
        co_return drkey::Key{
            reinterpret_cast<const std::byte*>(resp.key().data()),
            timepointFromProtobuf(resp.epoch_begin()),
            timepointFromProtobuf(resp.epoch_end()),
        };
    }

    /// \copydoc GrpcDaemonClient::rpcDRKeyASHost
    auto rpcDRKeyASHost(const DRKeyASHostRequest& asHostReq)
        -> boost::asio::awaitable<Maybe<drkey::Key>>
    {
        using boost::asio::use_awaitable;
        using rpc = agrpc::ClientRPC<
            &proto::daemon::v1::DaemonService::Stub::PrepareAsyncDRKeyASHost>;
        using namespace scion::details;

        grpc::ClientContext ctx;
        rpc::Request req;
        req.mutable_val_time()->set_seconds((std::uint32_t)(timepointSeconds(asHostReq.valTime)));
        req.mutable_val_time()->set_nanos((std::uint32_t)(timepointNanos(asHostReq.valTime)));
        req.set_protocol_id(static_cast<proto::drkey::v1::Protocol>(asHostReq.protocol));
        req.set_src_ia(asHostReq.srcIA);
        req.set_dst_ia(asHostReq.dstIA);
        req.set_dst_host(asHostReq.dstHost);

        rpc::Response resp;
        auto status = co_await rpc::request(grpcCtx, stub, ctx, req, resp, use_awaitable);
        if (!status.ok()) co_return Error(status.error_code());
        co_return drkey::Key{
            reinterpret_cast<const std::byte*>(resp.key().data()),
            timepointFromProtobuf(resp.epoch_begin()),
            timepointFromProtobuf(resp.epoch_end()),
        };
    }

    /// \copydoc GrpcDaemonClient::rpcDRKeyHostHost
    auto rpcDRKeyHostHost(const DRKeyHostHostRequest& hostHostReq)
        -> boost::asio::awaitable<Maybe<drkey::Key>>
    {
        using boost::asio::use_awaitable;
        using rpc = agrpc::ClientRPC<
            &proto::daemon::v1::DaemonService::Stub::PrepareAsyncDRKeyHostHost>;
        using namespace scion::details;

        grpc::ClientContext ctx;
        rpc::Request req;
        req.mutable_val_time()->set_seconds((std::uint32_t)(timepointSeconds(hostHostReq.valTime)));
        req.mutable_val_time()->set_nanos((std::uint32_t)(timepointNanos(hostHostReq.valTime)));
        req.set_protocol_id(static_cast<proto::drkey::v1::Protocol>(hostHostReq.protocol));
        req.set_src_ia(hostHostReq.srcIA);
        req.set_dst_ia(hostHostReq.dstIA);
        req.set_src_host(hostHostReq.srcHost);
        req.set_dst_host(hostHostReq.dstHost);

        rpc::Response resp;
        auto status = co_await rpc::request(grpcCtx, stub, ctx, req, resp, use_awaitable);
        if (!status.ok()) co_return Error(status.error_code());
        co_return drkey::Key{
            reinterpret_cast<const std::byte*>(resp.key().data()),
            timepointFromProtobuf(resp.epoch_begin()),
            timepointFromProtobuf(resp.epoch_end()),
        };
    }
};

} // namespace daemon
} // namespace scion
