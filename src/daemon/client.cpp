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

#include "scion/daemon/client.hpp"
#include "scion/proto/daemon/v1/daemon.grpc.pb.h"

#include <system_error>
#include <type_traits>
#include <variant>


struct GrpcErrorCategory : public std::error_category
{
    const char* name() const noexcept override
    {
        return "grpc";
    }

    std::string message(int code) const override
    {
        using grpc::StatusCode;
        switch (static_cast<StatusCode>(code)) {
            case StatusCode::OK:
                return "success";
            case StatusCode::CANCELLED:
                return "operation was cancelled";
            case StatusCode::UNKNOWN:
                return "unknown error";
            case StatusCode::INVALID_ARGUMENT:
                return "client specified an invalid argument";
            case StatusCode::DEADLINE_EXCEEDED:
                return "deadline expired before operation could complete";
            case StatusCode::NOT_FOUND:
                return "requested entity not found";
            case StatusCode::ALREADY_EXISTS:
                return "entity that was attempted to create already exists";
            case StatusCode::PERMISSION_DENIED:
                return "caller does not have permissions to execute operation";
            case StatusCode::UNAUTHENTICATED:
                return "request does not have valid credentials";
            case StatusCode::RESOURCE_EXHAUSTED:
                return "some resource has been exhausted";
            case StatusCode::FAILED_PRECONDITION:
                return "precondition failed";
            case StatusCode::ABORTED:
                return "operation aborted due to an issue";
            case StatusCode::OUT_OF_RANGE:
                return "operation was attempted past the valid range";
            case StatusCode::UNIMPLEMENTED:
                return "operation is not implemented or supported";
            case StatusCode::INTERNAL:
                return "internal error";
            case StatusCode::UNAVAILABLE:
                return "service currently not available";
            case StatusCode::DATA_LOSS:
                return "unrecoverable data loss or corruption";
            default:
                return "unexpected error code";
        }
    }

    bool equivalent(int code, const std::error_condition& cond) const noexcept override
    {
        using grpc::StatusCode;
        using scion::ErrorCondition;
        if (cond.category() == scion::scion_error_condition()) {
            const auto value = static_cast<ErrorCondition>(cond.value());
            if (value == ErrorCondition::ControlPlaneRPCError) return true;
            switch (static_cast<StatusCode>(code)) {
            case StatusCode::OK:
                return value == ErrorCondition::Ok;
            case StatusCode::CANCELLED:
                return value == ErrorCondition::Cancelled;
            case StatusCode::INVALID_ARGUMENT:
                return value == ErrorCondition::InvalidArgument;
            case StatusCode::OUT_OF_RANGE:
                return value == ErrorCondition::InvalidArgument;
            case StatusCode::UNIMPLEMENTED:
                return value == ErrorCondition::NotImplemented;
            case StatusCode::INTERNAL:
                return value == ErrorCondition::LogicError;
            default:
                return false;
            }
        }
        return false;
    }
};

static GrpcErrorCategory grpcErrorCategory;

const std::error_category& scion::grpc_error_category()
{
    return grpcErrorCategory;
}

std::error_code grpc::make_error_code(grpc::StatusCode code)
{
    return {static_cast<int>(code), grpcErrorCategory};
}

namespace scion {
namespace daemon {
namespace details {

Maybe<PathPtr> pathFromProtobuf(IsdAsn src, IsdAsn dst,
    const proto::daemon::v1::Path& pb, PathReqFlagSet flags)
{
    auto nh = generic::IPEndpoint::Parse(pb.interface().address().address(), false);
    if (isError(nh)) return propagateError(nh);

    auto& raw = pb.raw();
    auto path = makePath(
        src, dst, hdr::PathType::SCION,
        scion::details::timepointFromProtobuf(pb.expiration()),
        (std::uint16_t)std::min(pb.mtu(), 65535u),
        *nh,
        std::span<const std::byte>(
            reinterpret_cast<const std::byte*>(raw.data()),
            reinterpret_cast<const std::byte*>(raw.data()) + raw.size())
    );

    if (flags[PathReqFlags::Interfaces]) {
        path->addAttribute<path_meta::Interfaces>(PATH_ATTRIBUTE_INTERFACES)->initialize(pb);
    }
    if (flags[PathReqFlags::HopMetadata]) {
        path->addAttribute<path_meta::HopMetadata>(PATH_ATTRIBUTE_HOP_META)->initialize(pb);
    }
    if (flags[PathReqFlags::LinkMetadata]) {
        path->addAttribute<path_meta::LinkMetadata>(PATH_ATTRIBUTE_LINK_META)->initialize(pb);
    }

    return path;
}

} // namespace details
} // namespace daemon
} // namespace scion
