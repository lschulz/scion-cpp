// Copyright (c) 2026 Lars-Christian Schulz
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

#include "scion/addr/generic_ip.hpp"
#include "scion/bit_stream.hpp"
#include "scion/details/flags.hpp"
#include "scion/error_codes.hpp"
#include "scitra/mptcpd_types.hpp"

#include <cstdint>
#include <optional>
#include <vector>


namespace scion {
namespace scitra {
namespace mptcpd {

template <typename Stream, typename Error>
bool serialize(generic::IPAddress& addr, Stream& stream, Error& err)
{
    std::uint32_t is4 = addr.is4();
    if (!stream.serializeUint32(is4, err)) return err.propagate();
    if (!addr.serialize(stream, is4, err)) return err.propagate();
    return true;
}

template <typename Stream, typename Error>
bool serialize(generic::IPEndpoint& addr, Stream& stream, Error& err)
{
    generic::IPAddress ip = addr.host();
    std::uint16_t port = addr.port();
    bool is4 = addr.host().is4();

    if (!stream.serializeUint16(is4, err)) return err.propagate();
    if (!stream.serializeUint16(port, err)) return err.propagate();
    if (!ip.serialize(stream, is4, err)) return err.propagate();

    addr = generic::IPEndpoint(ip, port);
    return true;
}

// TODO: Move somewhere else and add unit test
template <typename Stream, typename Error>
bool serialize(std::string& str, Stream& stream, Error& err)
{
    std::uint32_t size = 0;
    if constexpr (Stream::IsWriting) {
        std::size_t s = str.size();
        if (s > (std::size_t)std::numeric_limits<std::uint32_t>::max()) {
            return err.error("String too long");
        }
        size = (std::uint32_t)s;
    }
    if (!stream.serializeUint32(size, err)) return err.propagate();
    if (Stream::IsReading) str.resize(size);
    std::span<std::byte> data(reinterpret_cast<std::byte*>(str.data()), size);
    if (!stream.serializeBytes(data, err)) return err.propagate();
    return true;
}

// TODO: Move somewhere else and add unit test
template <
    typename T,
    typename Stream,
    typename Error>
bool serialize(std::vector<T>& v, Stream& stream, Error& err)
{
    std::uint32_t size = 0;
    if constexpr (Stream::IsWriting) {
        std::size_t s = v.size();
        if (s > (std::size_t)std::numeric_limits<std::uint32_t>::max()) {
            return err.error("Input array too large");
        }
        size = (std::uint32_t)s;
    }
    if (!stream.serializeUint32(size, err)) return err.propagate();
    if (Stream::IsReading) v.resize(size);
    for (auto& x : v) {
        if (!serialize(x, stream, err)) return err.propagate();
    }
    return true;
}

template <typename Stream, typename Error>
bool serialize(MpTcpLimit& limit, Stream& stream, Error& err)
{
    if (!stream.advanceBytes(2, err)) return err.propagate();
    if (!stream.serializeUint16(limit.type, err)) return err.propagate();
    if (!stream.serializeUint32(limit.limit, err)) return err.propagate();
    return true;
}

template <typename Stream, typename Error>
bool serialize(AddrInfo& addrinfo, Stream& stream, Error& err)
{
    if (!mptcpd::serialize(addrinfo.addr, stream, err)) return err.propagate();
    if (!stream.advanceBytes(3, err)) return err.propagate();
    if (!stream.serializeByte(addrinfo.id, err)) return err.propagate();
    if (!stream.serializeUint32(addrinfo.flags, err)) return err.propagate();
    if (!stream.serializeUint32(addrinfo.index, err)) return err.propagate();
    return true;
}

template <typename Stream, typename Error>
bool serialize(Interface& iface, Stream& stream, Error& err)
{
    if (!stream.advanceBytes(1, err)) return err.propagate();
    if (!stream.serializeByte(iface.family, err)) return err.propagate();
    if (!stream.serializeUint16(iface.type, err)) return err.propagate();
    if (!stream.serializeUint32(iface.flags, err)) return err.propagate();
    if (!mptcpd::serialize(iface.name, stream, err)) return err.propagate();
    if (!mptcpd::serialize(iface.addresses, stream, err)) return err.propagate();
    return true;
}

namespace details {

class NewConnection
{
public:
    static constexpr Function function = Function::NewConnection;
    Token token = 0;
    generic::IPEndpoint localAddr;
    generic::IPEndpoint remoteAddr;
    enum class Flags : std::uint32_t
    {
        ServerSide  =  1 << 0,
        DenyJoinId0 =  1 << 1,
    };
    using FlagSet = scion::details::FlagSet<Flags>;
    FlagSet flags;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(token, err)) return err.propagate();
        if (!stream.serializeUint32(flags.ref(), err)) return err.propagate();
        if (!mptcpd::serialize(localAddr, stream, err)) return err.propagate();
        if (!mptcpd::serialize(remoteAddr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(flags.ref(), err)) return err.propagate();
        return true;
    }
};

inline NewConnection::FlagSet operator|(NewConnection::Flags lhs, NewConnection::Flags rhs)
{
    return NewConnection::FlagSet(lhs) | rhs;
}

class ConnectionEstablished
{
public:
    static constexpr Function function = Function::ConnectionEstablished;
    Token token = 0;
    generic::IPEndpoint localAddr;
    generic::IPEndpoint remoteAddr;
    enum class Flags : std::uint32_t
    {
        ServerSide  =  1 << 0,
        DenyJoinId0 =  1 << 1,
    };
    using FlagSet = scion::details::FlagSet<Flags>;
    FlagSet flags;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(token, err)) return err.propagate();
        if (!mptcpd::serialize(localAddr, stream, err)) return err.propagate();
        if (!mptcpd::serialize(remoteAddr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(flags.ref(), err)) return err.propagate();
        return true;
    }
};

inline ConnectionEstablished::FlagSet operator|(
    ConnectionEstablished::Flags lhs, ConnectionEstablished::Flags rhs)
{
    return ConnectionEstablished::FlagSet(lhs) | rhs;
}

class ConnectionClosed
{
public:
    static constexpr Function function = Function::ConnectionClosed;
    Token token = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(token, err)) return err.propagate();
        return true;
    }
};

class NewAddress
{
public:
    static constexpr Function function = Function::NewAddress;
    Token token = 0;
    AddressId id = 0;
    generic::IPEndpoint addr;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(token, err)) return err.propagate();
        if (!stream.advanceBytes(3, err)) return err.propagate();
        if (!stream.serializeByte(id, err)) return err.propagate();
        if (!mptcpd::serialize(addr, stream, err)) return err.propagate();
        return true;
    }
};

class AddressRemoved
{
public:
    static constexpr Function function = Function::AddressRemoved;
    Token token = 0;
    AddressId id = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(token, err)) return err.propagate();
        if (!stream.advanceBytes(3, err)) return err.propagate();
        if (!stream.serializeByte(id, err)) return err.propagate();
        return true;
    }
};

/// \brief Notification: A new subflow was established.
class NewSubflow
{
public:
    static constexpr Function function = Function::NewSubflow;
    Token token = 0;
    generic::IPEndpoint localAddr;
    generic::IPEndpoint remoteAddr;
    bool backup = false;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(token, err)) return err.propagate();
        if (!mptcpd::serialize(localAddr, stream, err)) return err.propagate();
        if (!mptcpd::serialize(remoteAddr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(backup, err)) return err.propagate();
        return true;
    }
};

class SubflowClosed
{
public:
    static constexpr Function function = Function::SubflowClosed;
    Token token = 0;
    generic::IPEndpoint localAddr;
    generic::IPEndpoint remoteAddr;
    bool backup = false;
    std::uint8_t error = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(token, err)) return err.propagate();
        if (!mptcpd::serialize(localAddr, stream, err)) return err.propagate();
        if (!mptcpd::serialize(remoteAddr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(backup, err)) return err.propagate();
        if (!stream.serializeUint32(error, err)) return err.propagate();
        return true;
    }
};

class SubflowPriority
{
public:
    static constexpr Function function = Function::SubflowPriority;
    Token token = 0;
    generic::IPEndpoint localAddr;
    generic::IPEndpoint remoteAddr;
    bool backup = false;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(token, err)) return err.propagate();
        if (!mptcpd::serialize(localAddr, stream, err)) return err.propagate();
        if (!mptcpd::serialize(remoteAddr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(backup, err)) return err.propagate();
        return true;
    }
};

class ListenerCreated
{
public:
    static constexpr Function function = Function::ListenerCreated;
    generic::IPEndpoint localAddr;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(localAddr, stream, err)) return err.propagate();
        return true;
    }
};

class ListenerClosed
{
public:
    static constexpr Function function = Function::ListenerClosed;
    generic::IPEndpoint localAddr;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(localAddr, stream, err)) return err.propagate();
        return true;
    }
};

class NewInterface
{
public:
    static constexpr Function function = Function::NewInterface;
    Interface interface;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(interface, stream, err)) return err.propagate();
        return true;
    }
};

class UpdateInterface
{
public:
    static constexpr Function function = Function::UpdateInterface;
    Interface interface;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(interface, stream, err)) return err.propagate();
        return true;
    }
};

class DeleteInterface
{
public:
    static constexpr Function function = Function::DeleteInterface;
    Interface interface;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(interface, stream, err)) return err.propagate();
        return true;
    }
};

class NewLocalAddress
{
public:
    static constexpr Function function = Function::NewLocalAddress;
    Interface interface;
    generic::IPAddress addr;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(interface, stream, err)) return err.propagate();
        if (!mptcpd::serialize(addr, stream, err)) return err.propagate();
        return true;
    }
};

class DeleteLocalAddress
{
public:
    static constexpr Function function = Function::DeleteLocalAddress;
    Interface interface;
    generic::IPAddress addr;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(interface, stream, err)) return err.propagate();
        if (!mptcpd::serialize(addr, stream, err)) return err.propagate();
        return true;
    }
};

class PmIsReady // TODO: Rename IsReady -> Ready
{
public:
    static constexpr Function function = Function::PmAddAddr;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class PmAddAddr
{
public:
    static constexpr Function function = Function::PmAddAddr;
    generic::IPEndpoint in_addr;
    AddressId in_id = 0;
    Token in_token = 0;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(in_addr, stream, err)) return err.propagate();
        if (!stream.advanceBytes(3, err)) return err.propagate();
        if (!stream.serializeByte(in_id, err)) return err.propagate();
        if (!stream.serializeUint32(in_token, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class PmAddAddrNoListener
{
public:
    static constexpr Function function = Function::PmAddAddrNoListener;
    generic::IPEndpoint in_addr;
    AddressId in_id = 0;
    Token in_token = 0;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(in_addr, stream, err)) return err.propagate();
        if (!stream.advanceBytes(3, err)) return err.propagate();
        if (!stream.serializeByte(in_id, err)) return err.propagate();
        if (!stream.serializeUint32(in_token, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class PmRemoveAddr
{
public:
    static constexpr Function function = Function::PmRemoveAddr;
    generic::IPEndpoint in_addr;
    AddressId in_id = 0;
    Token in_token = 0;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(in_addr, stream, err)) return err.propagate();
        if (!stream.advanceBytes(3, err)) return err.propagate();
        if (!stream.serializeByte(in_id, err)) return err.propagate();
        if (!stream.serializeUint32(in_token, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class PmAddSubflow
{
public:
    static constexpr Function function = Function::PmAddSubflow;
    Token in_token = 0;
    AddressId in_localAddrId = 0;
    AddressId in_remoteAddrId = 0;
    std::optional<generic::IPEndpoint> in_localAddr;
    generic::IPEndpoint in_remoteAddr;
    bool in_backup = false;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        bool localAddrHasValue = in_localAddr.has_value();
        if (!stream.serializeUint32(in_token, err)) return err.propagate();
        if (!stream.serializeByte(in_localAddrId, err)) return err.propagate();
        if (!stream.serializeByte(in_remoteAddrId, err)) return err.propagate();
        if (!stream.serializeUint16(localAddrHasValue, err)) return err.propagate();
        if (localAddrHasValue) {
            if (!mptcpd::serialize(*in_localAddr, stream, err)) return err.propagate();
        }
        if (!mptcpd::serialize(in_remoteAddr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(in_backup, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class PmSetBackup
{
public:
    static constexpr Function function = Function::PmSetBackup;
    Token in_token = 0;
    generic::IPEndpoint in_localAddr;
    generic::IPEndpoint in_remoteAddr;
    bool in_backup = false;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(in_token, err)) return err.propagate();
        if (!mptcpd::serialize(in_localAddr, stream, err)) return err.propagate();
        if (!mptcpd::serialize(in_remoteAddr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(in_backup, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class PmRemoveSubflow
{
public:
    static constexpr Function function = Function::PmRemoveSubflow;
    Token in_token = 0;
    generic::IPEndpoint in_localAddr;
    generic::IPEndpoint in_remoteAddr;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(in_token, err)) return err.propagate();
        if (!mptcpd::serialize(in_localAddr, stream, err)) return err.propagate();
        if (!mptcpd::serialize(in_remoteAddr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class KpmAddAddr
{
public:
    static constexpr Function function = Function::KpmAddAddr;
    generic::IPEndpoint in_addr;
    AddressId in_id = 0;
    MpTcpFlags in_flags = 0;
    int in_index = 0;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(in_addr, stream, err)) return err.propagate();
        if (!stream.advanceBytes(3, err)) return err.propagate();
        if (!stream.serializeByte(in_id, err)) return err.propagate();
        if (!stream.serializeUint32(in_flags, err)) return err.propagate();
        if (!stream.serializeUint32(in_index, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class KpmRemoveAddr
{
public:
    static constexpr Function function = Function::KpmRemoveAddr;
    AddressId in_id = 0;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.advanceBytes(3, err)) return err.propagate();
        if (!stream.serializeByte(in_id, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class KpmGetAddr
{
public:
    static constexpr Function function = Function::KpmGetAddr;
    AddressId in_id = 0;
    AddrInfo out_addrinfo;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.advanceBytes(3, err)) return err.propagate();
        if (!stream.serializeByte(in_id, err)) return err.propagate();
        if (!mptcpd::serialize(out_addrinfo, stream, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class KpmDumpAddrs
{
public:
    static constexpr Function function = Function::KpmDumpAddrs;
    std::vector<AddrInfo> out_addrinfo;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (mptcpd::serialize(out_addrinfo, stream, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class KpmFlushAddrs
{
public:
    static constexpr Function function = Function::KpmFlushAddrs;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class KpmSetLimits
{
public:
    static constexpr Function function = Function::KpmSetLimits;
    std::vector<MpTcpLimit> in_limits;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (mptcpd::serialize(in_limits, stream, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class KpmGetLimits
{
public:
    static constexpr Function function = Function::KpmGetLimits;
    std::vector<MpTcpLimit> out_limits;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (mptcpd::serialize(out_limits, stream, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

class KpmSetFlags
{
public:
    static constexpr Function function = Function::KpmSetFlags;
    generic::IPEndpoint in_addr;
    MpTcpFlags in_flags = 0;
    int out_result = 0;

public:
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!mptcpd::serialize(in_addr, stream, err)) return err.propagate();
        if (!stream.serializeUint32(in_flags, err)) return err.propagate();
        if (!stream.serializeUint32(out_result, err)) return err.propagate();
        return true;
    }
};

} // namespace details
} // namespace mptcpd
} // namespace scitra
} // namespace scion
