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

#include <ell/log.h>
#include <ell/queue.h>
#include <ell/util.h>
#include <mptcpd/addr_info.h>
#include <mptcpd/network_monitor.h>
#include <mptcpd/path_manager.h>

#include "scion/addr/generic_ip.hpp"
#include "scion/details/bit.hpp"
#include "scion/posix/sockaddr.hpp"
#include "scitra/ipc_channel.hpp"
#include "scitra/mptcpd.hpp"

#include <boost/asio.hpp>

#include <atomic>
#include <cstring>
#include <future>
#include <memory>
#include <thread>

namespace asio = boost::asio;
using namespace scion::generic;
using namespace scion::scitra;
using namespace scion::scitra::mptcpd::details;
using local_stream = asio::local::stream_protocol;
using scion::details::byteswapBE;

static const uint32_t IPC_MAGIC = 0x77846780; // MTCP
static constexpr size_t RECEIVE_BUF_SIZE = 256;
static constexpr size_t SEND_BUF_SIZE = 256;

static std::thread ipcThread; // TODO: Add prefix?
static boost::asio::io_context ioCtx;
static local_stream::acceptor acceptor(ioCtx);
static scion::scitra::IpcChannel channel(ioCtx, IPC_MAGIC);
static std::atomic<bool> acceptConnection = false;

static TxID seqOut = 0x800000;
static struct mptcpd_pm* pathManager = nullptr;

// TODO: Locks
// TODO: Tests

static void executeCommand(uint32_t func, scion::scitra::TxID seq, std::span<std::byte> raw);

static asio::awaitable<int> accept(const char* bind)
{
    static std::array<std::byte, SEND_BUF_SIZE> buffer;

    if (std::strlen(bind) > 91) {
        l_error("Scitra: Socket path too long (%d)", errno);
        co_return -1;
    }

    while (acceptConnection) {
        acceptor.open();
        acceptor.bind(local_stream::endpoint(bind));
        acceptor.listen(1);
        scion::scitra::IpcChannel channel(
            co_await acceptor.async_accept(asio::use_awaitable),
            IPC_MAGIC);
        acceptor.close();
        l_info("Scitra: Client connected");
        while (channel.isOpen()) {
            auto [buf, func, seq, ec] = co_await channel.receive(buffer);
            executeCommand(func, seq, buf);
        }
    }
}

// shared between all instantiations of sendMessage
static std::array<std::byte, SEND_BUF_SIZE> sendMessageBuffer;

template <typename Message>
static void sendMessage(Message& msg, TxID seq)
{
    scion::WriteStream ws(sendMessageBuffer);
    if (!msg.serialize(ws, scion::NullStreamError)) {
        l_error("Scitra: IPC failed: Message serialization failed");
        return;
    }
    std::span data(sendMessageBuffer.data(), ws.getPos().first);
    auto ec = channel.send((uint32_t)msg.function, seq, data);
    if (ec) {
        l_error("Scitra: IPC failed: %s", ec.message().c_str());
    }
}

static void toSockaddr(const IPEndpoint& ep, sockaddr_storage* sa)
{
    std::memset(sa, 0, sizeof(sockaddr_storage));
    if (ep.host().is4()) {
        auto in = reinterpret_cast<sockaddr_in*>(sa);
        in->sin_family = AF_INET;
        ep.host().toBytes4(std::span<std::byte, 4>(reinterpret_cast<std::byte*>(&in->sin_addr), 4));
        in->sin_port = byteswapBE(ep.port());
    } else {
        auto in6 = reinterpret_cast<sockaddr_in6*>(sa);
        in6->sin6_family = AF_INET6;
        ep.host().toBytes16(std::span<std::byte, 16>(
            reinterpret_cast<std::byte*>(&in6->sin6_addr), 16));
        in6->sin6_port = byteswapBE(ep.port());
        in6->sin6_scope_id = ep.host().zoneId();
    }
}

static IPEndpoint toEndpoint(const struct sockaddr* addr)
{
    if (addr->sa_family == AF_INET)
        return toGenericEp(*reinterpret_cast<const sockaddr_in*>(addr));
    else if (addr->sa_family == AF_INET6)
        return toGenericEp(*reinterpret_cast<const sockaddr_in6*>(addr));
    else
        return IPEndpoint::UnspecifiedIPv4();
}

static IPAddress toIPAddress(const struct sockaddr* addr)
{
    if (addr->sa_family == AF_INET)
        return toGenericAddr(reinterpret_cast<const sockaddr_in*>(addr)->sin_addr);
    else if (addr->sa_family == AF_INET6)
        return toGenericAddr(reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr);
    else
        return IPAddress::UnspecifiedIPv4();
}

static mptcpd::Interface toInterface(const struct mptcpd_interface* i)
{
    mptcpd::Interface interface;
    interface.family = i->family;
    interface.type = i->type;
    interface.flags = i->flags;
    interface.name = std::string(i->name);
    auto entry = l_queue_get_entries(i->addrs);
    while (entry) {
        interface.addresses.push_back(
            toIPAddress(reinterpret_cast<sockaddr*>(entry->data)));
        entry = entry->next;
    }
    return interface;
}

static void executeCommand(uint32_t func, scion::scitra::TxID seq, std::span<std::byte> raw)
{
    using scion::scitra::mptcpd::Function;
    using scion::NullStreamError;
    // TODO: Lock and check g_pm

    scion::ReadStream rs(raw);

    switch (static_cast<Function>(func)) {
    case Function::PmReady:
    {
        PmIsReady m;
        if (m.serialize(rs, NullStreamError)) {
            m.out_result = mptcpd_pm_ready(pathManager);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::PmAddAddr:
    {
        PmAddAddr m;
        if (m.serialize(rs, NullStreamError)) {
            sockaddr_storage sa;
            toSockaddr(m.in_addr, &sa);
            m.out_result = mptcpd_pm_add_addr(pathManager,
                reinterpret_cast<sockaddr*>(&sa), m.in_id, m.in_token);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::PmAddAddrNoListener:
    {
        PmAddAddrNoListener m;
        if (m.serialize(rs, NullStreamError)) {
            sockaddr_storage sa;
            toSockaddr(m.in_addr, &sa);
            mptcpd_pm_add_addr_no_listener(pathManager,
                reinterpret_cast<sockaddr*>(&sa), m.in_id, m.in_token);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::PmRemoveAddr:
    {
        PmRemoveAddr m;
        if (m.serialize(rs, NullStreamError)) {
            sockaddr_storage sa;
            toSockaddr(m.in_addr, &sa);
            m.out_result = mptcpd_pm_remove_addr(pathManager,
                reinterpret_cast<sockaddr*>(&sa), m.in_id, m.in_token);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::PmAddSubflow:
    {
        PmAddSubflow m;
        if (m.serialize(rs, NullStreamError)) {
            sockaddr_storage local, remote;
            if (m.in_localAddr)
                toSockaddr(m.in_localAddr.value(), &local);
            toSockaddr(m.in_remoteAddr, &remote);
            m.out_result = mptcpd_pm_add_subflow(pathManager,
                m.in_token, m.in_localAddrId, m.in_remoteAddrId,
                m.in_localAddr ? reinterpret_cast<sockaddr*>(&local) : NULL,
                reinterpret_cast<sockaddr*>(&remote),
                m.in_backup);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::PmSetBackup:
    {
        PmSetBackup m;
        if (m.serialize(rs, NullStreamError)) {
            sockaddr_storage local, remote;
            toSockaddr(m.in_localAddr, &local);
            toSockaddr(m.in_remoteAddr, &remote);
            m.out_result = mptcpd_pm_set_backup(pathManager,
                m.in_token,
                reinterpret_cast<sockaddr*>(&local),
                reinterpret_cast<sockaddr*>(&remote),
                m.in_backup);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::PmRemoveSubflow:
    {
        PmRemoveSubflow m;
        if (m.serialize(rs, NullStreamError)) {
            sockaddr_storage local, remote;
            toSockaddr(m.in_localAddr, &local);
            toSockaddr(m.in_remoteAddr, &remote);
            m.out_result = mptcpd_pm_remove_subflow(pathManager,
                m.in_token,
                reinterpret_cast<sockaddr*>(&local),
                reinterpret_cast<sockaddr*>(&remote));
            sendMessage(m, seq);
        }
        break;
    }
    case Function::KpmAddAddr:
    {
        KpmAddAddr m;
        if (m.serialize(rs, NullStreamError)) {
            sockaddr_storage sa;
            toSockaddr(m.in_addr, &sa);
            m.out_result = mptcpd_kpm_add_addr(pathManager,
                reinterpret_cast<sockaddr*>(&sa), m.in_id, m.in_flags, m.in_index);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::KpmRemoveAddr:
    {
        KpmRemoveAddr m;
        if (m.serialize(rs, NullStreamError)) {
            m.out_result = mptcpd_kpm_remove_addr(pathManager, m.in_id);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::KpmGetAddr:
    {
        auto m = std::make_unique<std::pair<TxID, KpmGetAddr>>();
        m->first = seq;
        if (m->second.serialize(rs, NullStreamError)) {
            int result = mptcpd_kpm_get_addr(pathManager, m->second.in_id,
                [] (mptcpd_addr_info const* info, void* data) {
                    auto m = reinterpret_cast<std::pair<TxID, KpmGetAddr>*>(data);
                    m->second.out_addrinfo.addr = toIPAddress(mptcpd_addr_info_get_addr(info));
                    m->second.out_addrinfo.id = mptcpd_addr_info_get_id(info);
                    m->second.out_addrinfo.flags = mptcpd_addr_info_get_flags(info);
                    m->second.out_addrinfo.index = mptcpd_addr_info_get_index(info);
                },
                m.get(),
                [] (void* data) {
                    std::unique_ptr<std::pair<TxID, KpmGetAddr>>m(
                        reinterpret_cast<std::pair<TxID, KpmGetAddr>*>(data));
                    sendMessage(m->second, m->first);
                });
            if (result) {
                m->second.out_result = result;
                sendMessage(m->second, seq);
            } else {
                m.release();
            }
        }
        break;
    }
    case Function::KpmDumpAddrs:
    {
        auto m = std::make_unique<std::pair<TxID, KpmDumpAddrs>>();
        m->first = seq;
        if (m->second.serialize(rs, NullStreamError)) {
            int result = mptcpd_kpm_dump_addrs(pathManager,
                [] (const mptcpd_addr_info* info, void* data) {
                    auto m = reinterpret_cast<std::pair<TxID, KpmDumpAddrs>*>(data);
                    m->second.out_addrinfo.emplace_back(
                        toIPAddress(mptcpd_addr_info_get_addr(info)),
                        mptcpd_addr_info_get_id(info),
                        mptcpd_addr_info_get_flags(info),
                        mptcpd_addr_info_get_index(info));
                },
                m.get(),
                [] (void* data) {
                    std::unique_ptr<std::pair<TxID, KpmDumpAddrs>>m(
                        reinterpret_cast<std::pair<TxID, KpmDumpAddrs>*>(data));
                    sendMessage(m->second, m->first);
                });
            if (result) {
                m->second.out_result = result;
                sendMessage(m->second, seq);
            } else {
                m.release();
            }
        }
        break;
    }
    case Function::KpmFlushAddrs:
    {
        KpmFlushAddrs m;
        if (m.serialize(rs, NullStreamError)) {
            m.out_result = mptcpd_kpm_flush_addrs(pathManager);
            sendMessage(m, seq);
        }
        break;
    }
    case Function::KpmSetLimits:
    {
        KpmSetLimits m;
        if (m.serialize(rs, NullStreamError)) {
            m.out_result = mptcpd_kpm_set_limits(pathManager,
                // TODO: Replace MpTcpLimit type
                reinterpret_cast<mptcpd_limit*>(m.in_limits.data()), m.in_limits.size());
            sendMessage(m, seq);
        }
        break;
    }
    case Function::KpmGetLimits:
    {
        auto m = std::make_unique<std::pair<TxID, KpmGetLimits>>();
        m->first = seq;
        if (m->second.serialize(rs, NullStreamError)) {
            int result = mptcpd_kpm_get_limits(pathManager,
                [] (const mptcpd_limit* limits, size_t len, void* data) {
                    std::unique_ptr<std::pair<TxID, KpmGetLimits>>m(
                        reinterpret_cast<std::pair<TxID, KpmGetLimits>*>(data));
                    m->second.out_limits.reserve(len);
                    for (size_t i = 0; i < len; ++i) {
                        // TODO: Replace MpTcpLimit type
                        m->second.out_limits.push_back(*reinterpret_cast<const mptcpd::MpTcpLimit*>(&limits[i]));
                    }
                    sendMessage(m->second, m->first);
                }, m.get());
            if (result) {
                m->second.out_result = result;
                sendMessage(m->second, seq);
            } else {
                m.release();
            }
        }
        break;
    }
    case Function::KpmSetFlags:
    {
        KpmSetFlags m;
        if (m.serialize(rs, NullStreamError)) {
            sockaddr_storage sa;
            toSockaddr(m.in_addr, &sa);
            m.out_result = mptcpd_kpm_set_flags(pathManager,
                reinterpret_cast<sockaddr*>(&sa), m.in_flags);
            sendMessage(m, seq);
        }
        break;
    }
    default:
        l_warn("Scitra: IPC: Received invalid function %u", func);
        break;
    }
}

extern "C" {

int spawn_ipc_thread(struct mptcpd_pm* pm, const char* bind)
{
    if (ipcThread.joinable()) return -1;
    pathManager = pm;
    try {
        acceptConnection = true;
        asio::co_spawn(ioCtx, accept(bind), asio::detached);
        ipcThread = std::thread([] { ioCtx.run(); });
        return 0;
    }
    catch (const std::exception& e) {
        l_error("Scitra: Spawning thread failed (%s).", e.what());
        return -1;
    }
}

void stop_and_join_ipc_thread()
{
    if (ipcThread.joinable()) {
        acceptConnection = false;
        acceptor.close();
        channel.close();
        ipcThread.join();
        pathManager = nullptr;
    }
}

void NEW_CONNECTION(
    mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool server_side,
    bool deny_join_id0,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        NewConnection m;
        m.token = token;
        m.localAddr = toEndpoint(laddr);
        m.remoteAddr = toEndpoint(raddr);
        if (server_side) m.flags |= NewConnection::Flags::ServerSide;
        if (deny_join_id0) m.flags |= NewConnection::Flags::DenyJoinId0;
        sendMessage(m, seqOut++);
    }
}

void CONNECTION_ESTABLISHED(
    mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool server_side,
    bool deny_join_id0,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        ConnectionEstablished m;
        m.token = token;
        m.localAddr = toEndpoint(laddr);
        m.remoteAddr = toEndpoint(raddr);
        if (server_side) m.flags |= ConnectionEstablished::Flags::ServerSide;
        if (deny_join_id0) m.flags |= ConnectionEstablished::Flags::DenyJoinId0;
        sendMessage(m, seqOut++);
    }
}

void CONNECTION_CLOSED(mptcpd_token_t token, struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        ConnectionClosed m;
        m.token = token;
        sendMessage(m, seqOut++);
    }
}

void NEW_ADDRESS(
    mptcpd_token_t token,
    mptcpd_aid_t id,
    const struct sockaddr* addr,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        NewAddress m;
        m.token = token;
        m.addr = toEndpoint(addr);
        m.id = id;
        sendMessage(m, seqOut++);
    }
}

void ADDRESS_REMOVED(
    mptcpd_token_t token,
    mptcpd_aid_t id,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        AddressRemoved m;
        m.token = token;
        m.id = id;
        sendMessage(m, seqOut++);
    }
}

void NEW_SUBFLOW(
    mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool backup,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        NewSubflow m;
        m.token = token;
        m.localAddr = toEndpoint(laddr);
        m.remoteAddr = toEndpoint(raddr);
        m.backup = backup;
        sendMessage(m, seqOut++);
    }
}

void SUBFLOW_CLOSED(
    mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool backup,
    uint8_t error,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        SubflowClosed m;
        m.token = token;
        m.localAddr = toEndpoint(laddr);
        m.remoteAddr = toEndpoint(raddr);
        m.backup = backup;
        m.error = error;
        sendMessage(m, seqOut++);
    }
}

void SUBFLOW_PRIORITY(
    mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool backup,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        SubflowPriority m;
        m.token = token;
        m.localAddr = toEndpoint(laddr);
        m.remoteAddr = toEndpoint(raddr);
        m.backup = backup;
        sendMessage(m, seqOut++);
    }
}

void LISTENER_CREATED(
    const struct sockaddr* laddr,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        ListenerCreated m;
        m.localAddr = toEndpoint(laddr);
        sendMessage(m, seqOut++);
    }
}

void LISTENER_CLOSED(
    const struct sockaddr* laddr,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        ListenerClosed m;
        m.localAddr = toEndpoint(laddr);
        sendMessage(m, seqOut++);
    }
}

void NEW_INTERFACE(
    const struct mptcpd_interface* i,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        NewInterface m;
        m.interface = toInterface(i);
        sendMessage(m, seqOut++);
    }
}

void UPDATE_INTERFACE(
    const struct mptcpd_interface* i,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        UpdateInterface m;
        m.interface = toInterface(i);
        sendMessage(m, seqOut++);
    }
}

void DELETE_INTERFACE(
    const struct mptcpd_interface* i,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        DeleteInterface m;
        m.interface = toInterface(i);
        sendMessage(m, seqOut++);
    }
}

void NEW_LOCAL_ADDRESS(
    const struct mptcpd_interface* i,
    const struct sockaddr* sa,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        NewLocalAddress m;
        m.interface = toInterface(i);
        m.addr = toIPAddress(sa);
        sendMessage(m, seqOut++);
    }
}

void DELETE_LOCAL_ADDRESS(
    const struct mptcpd_interface* i,
    const struct sockaddr* sa,
    struct mptcpd_pm* pm)
{
    assert(pathManager == pm);
    if (channel.isOpen()) {
        DeleteLocalAddress m;
        m.interface = toInterface(i);
        m.addr = toIPAddress(sa);
        sendMessage(m, seqOut++);
    }
}

} // extern "C"
