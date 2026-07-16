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

#include "scitra/path_manager.hpp"
#include "scitra/mptcpd.hpp"


namespace scion {
namespace scitra {
namespace mptcpd {

template <typename Message>
std::error_code sendMessage(IpcChannel& ipc, Message& msg, TxID seq)
{
    std::array<std::byte, 64> buf;
    WriteStream ws(buf);
    if (!msg.serialize(ws, NullStreamError)) {
        return ErrorCode::LogicError;
    }
    return ipc.send((std::uint32_t)msg.function, seq, std::span(buf.data(), ws.getPos().first));
}

Maybe<TxID>PathManager::PmIsReady()
{
    details::PmIsReady msg;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::PmAddAddr(const generic::IPEndpoint& addr, AddressId id, Token token)
{
    details::PmAddAddr msg;
    msg.in_addr = addr;
    msg.in_id = id;
    msg.in_token = token;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::PmAddAddrNoListener(
    const generic::IPEndpoint& addr, AddressId id, Token token)
{
    details::PmAddAddrNoListener msg;
    msg.in_addr = addr;
    msg.in_id = id;
    msg.in_token = token;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::PmRemoveAddr(
    const generic::IPEndpoint& addr, AddressId id, Token token)
{
    details::PmRemoveAddr msg;
    msg.in_addr = addr;
    msg.in_id = id;
    msg.in_token = token;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::PmAddSubflow(
    Token token,
    AddressId localAddrId,
    AddressId remoteAddrId,
    const std::optional<generic::IPEndpoint>& localAddr,
    const generic::IPEndpoint& remoteAddr,
    bool backup)
{
    details::PmAddSubflow msg;
    msg.in_token = token;
    msg.in_localAddrId = localAddrId;
    msg.in_remoteAddrId = remoteAddrId;
    msg.in_localAddr = localAddr;
    msg.in_remoteAddr = remoteAddr;
    msg.in_backup = backup;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::PmSetBackup(
    Token token,
    const generic::IPEndpoint& localAddr,
    const generic::IPEndpoint& remoteAddr,
    bool backup)
{
    details::PmSetBackup msg;
    msg.in_token = token;
    msg.in_localAddr = localAddr;
    msg.in_remoteAddr = remoteAddr;
    msg.in_backup = backup;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::PmRemoveSubflow(
    Token token,
    const generic::IPEndpoint& localAddr,
    const generic::IPEndpoint& remoteAddr)
{
    details::PmRemoveSubflow msg;
    msg.in_token = token;
    msg.in_localAddr = localAddr;
    msg.in_remoteAddr = remoteAddr;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::KpmAddAddr(
    const generic::IPEndpoint& addr,
    AddressId id,
    MpTcpFlags flags,
    int index)
{
    details::KpmAddAddr msg;
    msg.in_addr = addr;
    msg.in_id = id;
    msg.in_flags = flags;
    msg.in_index = index;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::KpmRemoveAddr(AddressId id)
{
    details::KpmRemoveAddr msg;
    msg.in_id = id;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::KpmGetAddr(AddressId id)
{
    details::KpmGetAddr msg;
    msg.in_id = id;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::KpmDumpAddrs()
{
    details::KpmDumpAddrs msg;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::KpmFlushAddrs()
{
    details::KpmFlushAddrs msg;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::KpmSetLimits(std::span<MpTcpLimit> limits)
{
    details::KpmSetLimits msg;
    msg.in_limits.assign(limits.begin(), limits.end());
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::KpmGetLimits()
{
    details::KpmGetLimits msg;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

Maybe<TxID> PathManager::KpmSetFlags(const generic::IPEndpoint& addr, MpTcpFlags flags)
{
    details::KpmSetFlags msg;
    msg.in_addr = addr;
    msg.in_flags = flags;
    auto seq = m_seq.fetch_add(1);
    auto ec = sendMessage(m_ipc, msg, seq);
    if (ec) return Error(ec);
    return seq;
}

void PathManager::dispatchMessage(Function func, TxID seq, std::span<std::byte> raw)
{
    ReadStream rs(raw);
    switch (func) {
    case Function::NewConnection:
    {
        details::NewConnection m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpNewConnection(m.token, m.localAddr, m.remoteAddr,
                m.flags[details::NewConnection::Flags::ServerSide],
                m.flags[details::NewConnection::Flags::DenyJoinId0]);
        }
        break;
    }
    case Function::ConnectionEstablished:
    {
        details::ConnectionEstablished m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpConnectionEstablished(m.token, m.localAddr, m.remoteAddr,
                m.flags[details::ConnectionEstablished::Flags::ServerSide],
                m.flags[details::ConnectionEstablished::Flags::DenyJoinId0]);
        }
        break;
    }
    case Function::ConnectionClosed:
    {
        details::ConnectionClosed m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpConnectionClosed(m.token);
        }
        break;
    }
    case Function::NewAddress:
    {
        details::NewAddress m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpNewAddress(m.token, m.id, m.addr);
        }
        break;
    }
    case Function::AddressRemoved:
    {
        details::AddressRemoved m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpAddressRemoved(m.token, m.id);
        }
        break;
    }
    case Function::NewSubflow:
    {
        details::NewSubflow m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpdNewSubflow(m.token, m.localAddr, m.remoteAddr, m.backup);
        }
        break;
    }
    case Function::SubflowClosed:
    {
        details::SubflowClosed m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpSubflowClosed(m.token, m.localAddr, m.remoteAddr, m.backup, m.error);
        }
        break;
    }
    case Function::SubflowPriority:
    {
        details::SubflowPriority m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpSubflowPriority(m.token, m.localAddr, m.remoteAddr, m.backup);
        }
        break;
    }
    case Function::ListenerCreated:
    {
        details::ListenerCreated m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpListenerCreated(m.localAddr);
        }
        break;
    }
    case Function::ListenerClosed:
    {
        details::ListenerClosed m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpListenerClosed(m.localAddr);
        }
        break;
    }
    case Function::NewInterface:
    {
        details::NewInterface m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpNewInterface(m.interface);
        }
        break;
    }
    case Function::UpdateInterface:
    {
        details::UpdateInterface m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpUpdateInterface(m.interface);
        }
        break;
    }
    case Function::DeleteInterface:
    {
        details::DeleteInterface m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpDeleteInterface(m.interface);
        }
        break;
    }
    case Function::NewLocalAddress:
    {
        details::NewLocalAddress m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpNewLocalAddress(m.interface, m.addr);
        }
        break;
    }
    case Function::DeleteLocalAddress:
    {
        details::DeleteLocalAddress m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpDeleteLocalAddress(m.interface, m.addr);
        }
        break;
    }
    case Function::PmReady:
    {
        details::PmIsReady m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpPmReadyCompleted(seq, m.out_result);
        }
        break;
    }
    case Function::PmAddAddr:
    {
        details::PmAddAddr m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpPmAddAddrCompleted(seq, m.out_result, m.in_addr, m.in_id, m.in_token);
        }
        break;
    }
    case Function::PmAddAddrNoListener:
    {
        details::PmAddAddrNoListener m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpPmAddAddrNoListenerCompleted(
                seq, m.out_result, m.in_addr, m.in_id, m.in_token);
        }
        break;
    }
    case Function::PmRemoveAddr:
    {
        details::PmRemoveAddr m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpPmRemoveAddrCompleted(seq, m.out_result, m.in_addr, m.in_id, m.in_token);
        }
        break;
    }
    case Function::PmAddSubflow:
    {
        details::PmAddSubflow m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpPmAddSubflowCompleted(seq, m.out_result, m.in_token, m.in_localAddrId,
                m.in_remoteAddrId, m.in_localAddr, m.in_remoteAddr, m.in_backup);
        }
        break;
    }
    case Function::PmSetBackup:
    {
        details::PmSetBackup m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpPmSetBackupCompleted(seq, m.out_result, m.in_token,
                m.in_localAddr, m.in_remoteAddr);
        }
        break;
    }
    case Function::PmRemoveSubflow:
    {
        details::PmRemoveSubflow m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpPmRemoveSubflowCompleted(seq, m.out_result, m.in_token,
                m.in_localAddr, m.in_remoteAddr);
        }
        break;
    }
    case Function::KpmAddAddr:
    {
        details::KpmAddAddr m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpKpmAddAddrCompleted(seq, m.out_result, m.in_addr, m.in_id,
                m.in_flags, m.in_index);
        }
        break;
    }
    case Function::KpmRemoveAddr:
    {
        details::KpmRemoveAddr m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpKpmRemoveAddrCompleted(seq, m.out_result, m.in_id);
        }
        break;
    }
    case Function::KpmGetAddr:
    {
        details::KpmGetAddr m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpKpmGetAddrCompleted(seq, m.out_result, m.out_addrinfo, m.in_id);
        }
        break;
    }
    case Function::KpmDumpAddrs:
    {
        details::KpmDumpAddrs m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpKpmDumpAddrsCompleted(seq, m.out_result, m.out_addrinfo);
        }
        break;
    }
    case Function::KpmFlushAddrs:
    {
        details::KpmFlushAddrs m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpKpmFlushAddrsCompleted(seq, m.out_result);
        }
        break;
    }
    case Function::KpmSetLimits:
    {
        details::KpmSetLimits m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpKpmSetLimitsCompleted(seq, m.out_result, m.in_limits);
        }
        break;
    }
    case Function::KpmGetLimits:
    {
        details::KpmGetLimits m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpKpmGetLimitsCompleted(seq, m.out_result, m.out_limits);
        }
        break;
    }
    case Function::KpmSetFlags:
    {
        details::KpmSetFlags m;
        if (m.serialize(rs, NullStreamError)) {
            callbacks->mptcpKpmSetFlagsCompleted(seq, m.out_result, m.in_addr, m.in_flags);
        }
        break;
    }
    }
}

} // namespace mptcpd
} // namespace scitra
} // namespace scion
