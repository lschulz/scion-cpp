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
#include "scion/details/flags.hpp"
#include "scion/drkey/drkey.hpp"
#include "scion/error_codes.hpp"
#include "scion/path/path_meta.hpp"
#include "scion/path/path.hpp"

#include "proto/daemon/v1/daemon.grpc.pb.h"
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <type_traits>


namespace grpc {
std::error_code make_error_code(StatusCode code);
}

namespace std {
template <> struct is_error_code_enum<grpc::StatusCode> : true_type {};
}

namespace scion {

const std::error_category& grpc_error_category();

namespace daemon {

enum class PathReqFlags : std::uint32_t
{
    /// Ask daemon to fetch paths from path servers instead of replying from cache.
    Refresh      = 1 << 0,
    /// Request hidden paths.
    Hidden       = 1 << 1,
    /// Store interface IDs and ISD-ASNs in path attribute `PATH_ATTRIBUTE_INTERFACES`.
    Interfaces   = 1 << 2,
    /// Store hop metadata in path attribute `PATH_ATTRIBUTE_HOP_META`.
    HopMetadata  = 1 << 3,
    /// Store link metadata in path attribute `PATH_ATTRIBUTE_LINK_META`.
    LinkMetadata = 1 << 4,
    /// Store all available metadata in path attributes.
    AllMetadata  = Interfaces | HopMetadata | LinkMetadata,
};

using PathReqFlagSet = scion::details::FlagSet<PathReqFlags>;
inline PathReqFlagSet operator|(PathReqFlags lhs, PathReqFlags rhs)
{
    return PathReqFlagSet(lhs) | rhs;
}

struct AsInfo
{
    IsdAsn isdAsn = {};
    bool core = 0;
    std::uint32_t mtu = 0;
};

using PortRange = std::pair<std::uint16_t, std::uint16_t>;

enum class DRKeyProtocol : std::uint_fast16_t
{
    Generic = 0,
    SCMP = 1,
};

struct DRKeyHostASRequest
{
    std::chrono::utc_clock::time_point valTime;
    DRKeyProtocol protocol;
    IsdAsn srcIA;
    IsdAsn dstIA;
    std::string srcHost;
};

struct DRKeyASHostRequest
{
    std::chrono::utc_clock::time_point valTime;
    DRKeyProtocol protocol;
    IsdAsn srcIA;
    IsdAsn dstIA;
    std::string dstHost;
};

struct DRKeyHostHostRequest
{
    std::chrono::utc_clock::time_point valTime;
    DRKeyProtocol protocol;
    IsdAsn srcIA;
    IsdAsn dstIA;
    std::string srcHost;
    std::string dstHost;
};

namespace details {
Maybe<PathPtr> pathFromProtobuf(IsdAsn src, IsdAsn dst,
    const proto::daemon::v1::Path& pb, PathReqFlagSet flags);
}

/// \brief Synchronous SCION daemon client.
class GrpcDaemonClient
{
protected:
    proto::daemon::v1::DaemonService::Stub stub;

public:
    /// \brief Initialize the client.
    /// \param target Address of the SCION daemon to connect to.
    GrpcDaemonClient(const grpc::string& target)
        : stub(grpc::CreateChannel(target, grpc::InsecureChannelCredentials()))
    {}

    /// \brief Request SCION paths between two ASes.
    /// \param src Source AS
    /// \param dst Destination AS
    /// \param flags
    /// \param out Output iterator that receives available paths.
    template <std::output_iterator<PathPtr> OutIter>
    std::error_code rpcPaths(IsdAsn src, IsdAsn dst, PathReqFlagSet flags, OutIter out)
    {
        grpc::ClientContext ctx;
        proto::daemon::v1::PathsRequest request;
        request.set_source_isd_as(src);
        request.set_destination_isd_as(dst);
        request.set_refresh(flags[PathReqFlags::Refresh]);
        request.set_hidden(flags[PathReqFlags::Hidden]);

        proto::daemon::v1::PathsResponse response;
        auto status = stub.Paths(&ctx, request, &response);
        if (!status.ok()) return status.error_code();

        for (const auto& path : response.paths()) {
            auto cooked = details::pathFromProtobuf(src, dst, path, flags);
            if (cooked) *out++ = std::move(*cooked);
        }
        return status.error_code();
    }

    /// \brief Request information about an AS.
    Maybe<AsInfo> rpcAsInfo(IsdAsn isdAsn)
    {
        grpc::ClientContext ctx;
        proto::daemon::v1::ASRequest request;
        request.set_isd_as(isdAsn);

        proto::daemon::v1::ASResponse response;
        auto status = stub.AS(&ctx, request, &response);
        if (!status.ok()) return Error(status.error_code());

        return AsInfo {
            IsdAsn(response.isd_as()),
            response.core(),
            response.mtu(),
        };
    }

    /// \brief Request the mapping from service addresses to underlay addresses.
    template <std::output_iterator<std::pair<std::string, std::string>> OutIter>
    std::error_code rpcServices(OutIter out)
    {
        grpc::ClientContext ctx;
        proto::daemon::v1::ServicesRequest request;
        proto::daemon::v1::ServicesResponse response;
        auto status = stub.Services(&ctx, request, &response);
        if (!status.ok()) return status.error_code();

        for (const auto& elem : response.services()) {
            for (const auto& service : elem.second.services()) {
                *out++ = std::make_pair(elem.first, service.uri());
            }
        }
        return status.error_code();
    }

    /// \brief Returns the end host port range used for SCION in the daemon's AS.
    /// \return Pair of first and last hop in the port range; both inclusive.
    Maybe<PortRange> rpcPortRange()
    {
        grpc::ClientContext ctx;
        google::protobuf::Empty request;
        proto::daemon::v1::PortRangeResponse response;
        auto status = stub.PortRange(&ctx, request, &response);
        if (!status.ok()) return Error(status.error_code());
        return std::make_pair(response.dispatched_port_start(), response.dispatched_port_end());
    }

    /// \brief Get a Host-AS DRKey matching the request.
    Maybe<drkey::Key> rpcDRKeyHostAS(const DRKeyHostASRequest& hostASReq)
    {
        using namespace scion::details;

        grpc::ClientContext ctx;
        proto::daemon::v1::DRKeyHostASRequest req;
        req.mutable_val_time()->set_seconds((std::uint32_t)(timepointSeconds(hostASReq.valTime)));
        req.mutable_val_time()->set_nanos((std::uint32_t)(timepointNanos(hostASReq.valTime)));
        req.set_protocol_id(static_cast<proto::drkey::v1::Protocol>(hostASReq.protocol));
        req.set_src_ia(hostASReq.srcIA);
        req.set_dst_ia(hostASReq.dstIA);
        req.set_src_host(hostASReq.srcHost);

        proto::daemon::v1::DRKeyHostASResponse resp;
        auto status = stub.DRKeyHostAS(&ctx, req, &resp);
        if (!status.ok()) return Error(status.error_code());
        return drkey::Key{
            reinterpret_cast<const std::byte*>(resp.key().data()),
            timepointFromProtobuf(resp.epoch_begin()),
            timepointFromProtobuf(resp.epoch_end()),
        };
    }

    /// \brief Get an AS-Host DRKey matching the request.
    Maybe<drkey::Key> rpcDRKeyASHost(const DRKeyASHostRequest& asHostReq)
    {
        using namespace scion::details;

        grpc::ClientContext ctx;
        proto::daemon::v1::DRKeyASHostRequest req;
        req.mutable_val_time()->set_seconds((std::uint32_t)(timepointSeconds(asHostReq.valTime)));
        req.mutable_val_time()->set_nanos((std::uint32_t)(timepointNanos(asHostReq.valTime)));
        req.set_protocol_id(static_cast<proto::drkey::v1::Protocol>(asHostReq.protocol));
        req.set_src_ia(asHostReq.srcIA);
        req.set_dst_ia(asHostReq.dstIA);
        req.set_dst_host(asHostReq.dstHost);

        proto::daemon::v1::DRKeyASHostResponse resp;
        auto status = stub.DRKeyASHost(&ctx, req, &resp);
        if (!status.ok()) return Error(status.error_code());
        return drkey::Key{
            reinterpret_cast<const std::byte*>(resp.key().data()),
            timepointFromProtobuf(resp.epoch_begin()),
            timepointFromProtobuf(resp.epoch_end()),
        };
    }

    /// \brief Get a Host-Host DRKey matching the request.
    Maybe<drkey::Key> rpcDRKeyHostHost(const DRKeyHostHostRequest& hostHostReq)
    {
        using namespace scion::details;

        grpc::ClientContext ctx;
        proto::daemon::v1::DRKeyHostHostRequest req;
        req.mutable_val_time()->set_seconds((std::uint32_t)(timepointSeconds(hostHostReq.valTime)));
        req.mutable_val_time()->set_nanos((std::uint32_t)(timepointNanos(hostHostReq.valTime)));
        req.set_protocol_id(static_cast<proto::drkey::v1::Protocol>(hostHostReq.protocol));
        req.set_src_ia(hostHostReq.srcIA);
        req.set_dst_ia(hostHostReq.dstIA);
        req.set_src_host(hostHostReq.srcHost);
        req.set_dst_host(hostHostReq.dstHost);

        proto::daemon::v1::DRKeyHostHostResponse resp;
        auto status = stub.DRKeyHostHost(&ctx, req, &resp);
        if (!status.ok()) return Error(status.error_code());
        return drkey::Key{
            reinterpret_cast<const std::byte*>(resp.key().data()),
            timepointFromProtobuf(resp.epoch_begin()),
            timepointFromProtobuf(resp.epoch_end()),
        };
    }
};

} // namespace daemon
} // namespace scion
