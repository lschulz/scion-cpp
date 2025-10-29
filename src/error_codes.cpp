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

#include "scion/error_codes.hpp"

#include <format>


namespace scion {

struct ScionErrorCategory : public std::error_category
{
    const char* name() const noexcept
    {
        return "scion-cpp";
    }

    std::string message(int code) const
    {
        switch (static_cast<ErrorCode>(code)) {
            case ErrorCode::Ok:
                return "ok";
            case ErrorCode::Cancelled:
                return "operation cancelled";
            case ErrorCode::Pending:
                return "operation pending";
            case ErrorCode::Timeout:
                return "operation timed out";
            case ErrorCode::ScmpReceived:
                return "received an SCMP packet";
            case ErrorCode::LogicError:
                return "expected precondition failed";
            case ErrorCode::NotImplemented:
                return "not implemented ";
            case ErrorCode::InvalidArgument:
                return "invalid argument";
            case ErrorCode::SyntaxError:
                return "syntax error in input";
            case ErrorCode::InvalidSocket:
                return "socket closed or invalid";
            case ErrorCode::BufferTooSmall:
                return "provided buffer too small to hold output";
            case ErrorCode::PacketTooBig:
                return "packet or payload too big";
            case ErrorCode::RequiresZone:
                return "IPv6 address requires zone identifier";
            case ErrorCode::NoLocalHostAddr:
                return "no suitable underlay host address found";
            case ErrorCode::NameNotFound:
                return "name not found";
            case ErrorCode::RemoteError:
                return "remote machine returned an error";
            case ErrorCode::FileNotFound:
                return "file not found";
            case ErrorCode::InvalidPacket:
                return "received an invalid packet";
            case ErrorCode::ChecksumError:
                return "packet checksum incorrect";
            case ErrorCode::DstAddrMismatch:
                return "packet rejected because of unexpected destination address";
            case ErrorCode::SrcAddrMismatch:
                return "packet rejected because of unexpected source address";
            default:
                return "unexpected error code";
        }
    }
};

static ScionErrorCategory scionErrorCategory;

const std::error_category& scion_error_category()
{
    return scionErrorCategory;
}

std::error_code make_error_code(ErrorCode code)
{
    return {static_cast<int>(code), scionErrorCategory};
}

struct ScionErrorCondition : std::error_category
{
    const char* name() const noexcept
    {
        return "scion-cpp";
    }

    std::string message(int code) const
    {
        switch (static_cast<ErrorCondition>(code)) {
            case ErrorCondition::Ok:
                return "ok";
            case ErrorCondition::Cancelled:
                return "operation cancelled";
            case ErrorCondition::Pending:
                return "operation pending";
            case ErrorCondition::Timeout:
                return "operation timed out";
            case ErrorCondition::ScmpReceived:
                return "received an SCMP packet";
            case ErrorCondition::LogicError:
                return "expected precondition failed";
            case ErrorCondition::NotImplemented:
                return "not implemented ";
            case ErrorCondition::InvalidArgument:
                return "invalid argument";
            case ErrorCondition::SyntaxError:
                return "syntax error in input";
            case ErrorCondition::InvalidSocket:
                return "socket closed or invalid";
            case ErrorCondition::BufferTooSmall:
                return "provided buffer too small to hold output";
            case ErrorCondition::PacketTooBig:
                return "packet or payload too big";
            case ErrorCondition::RequiresZone:
                return "IPv6 address requires zone identifier";
            case ErrorCondition::NoLocalHostAddr:
                return "no suitable underlay host address found";
            case ErrorCondition::NameNotFound:
                return "name not found";
            case ErrorCondition::RemoteError:
                return "remote machine returned an error";
            case ErrorCondition::FileNotFound:
                return "file not found";
            case ErrorCondition::InvalidPacket:
                return "received an invalid packet";
            case ErrorCondition::ChecksumError:
                return "packet checksum incorrect";
            case ErrorCondition::DstAddrMismatch:
                return "packet rejected because of unexpected destination address";
            case ErrorCondition::SrcAddrMismatch:
                return "packet rejected because of unexpected source address";
            case ErrorCondition::WouldBlock:
                return "nonblocking operation would block";
            case ErrorCondition::ControlPlaneRPCError:
                return "error in communication with control plane services";
            default:
                return "Unexpected error code";
        }
    }

    bool equivalent(const std::error_code& ec, int condition) const noexcept
    {
        if (ec.category() == scionErrorCategory) {
            return ec.value() == condition;
        } else if (ec.category() == std::system_category()) {
            auto value = ec.value();
            switch (static_cast<ErrorCondition>(condition)) {
            case ErrorCondition::Ok:
                return value == 0;
            case ErrorCondition::Cancelled:
                return value == ECANCELED;
            case ErrorCondition::InvalidSocket:
                return value == EBADF || value == ENOTSOCK;
            case ErrorCondition::NoLocalHostAddr:
                return value == EDESTADDRREQ;
            case ErrorCondition::WouldBlock:
                // POSIX does not require EAGAIN and EWOULDBLOCK to have the same value
                return value == EAGAIN || value == EWOULDBLOCK;
            default:
                break;
            }
        }
        return false;
    }
};

static ScionErrorCondition scionErrorCondition;

const std::error_category& scion_error_condition()
{
    return scionErrorCategory;
}

std::error_condition make_error_condition(ErrorCondition code)
{
    return {static_cast<int>(code), scionErrorCondition};
}

std::string fmtError(std::error_code ec)
{
    return std::format("{}:{} {}", ec.category().name(), ec.value(), ec.message());
}

} // namespace scion
