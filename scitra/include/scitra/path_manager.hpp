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

#pragma once

#include "scion/error_codes.hpp"
#include "scitra/ipc_channel.hpp"
#include "scitra/mptcpd_types.hpp"

#include <spdlog/spdlog.h>

#include <atomic>
#include <vector>


namespace scion {
namespace scitra {
namespace mptcpd {

class PathManagerCallbacks
{
private:
    /// Path Manager Event Handlers ///

    /// \brief Notification: A new MPTCP connections was created.
    virtual void mptcpNewConnection(
        Token token, const generic::IPEndpoint& localAddr, const generic::IPEndpoint& remoteAddr,
        bool serverSide, bool denyJoinId0)
    {
        spdlog::debug(
            "MPTCP[{:08x}]: New connection {} -> {} (server_side: {}, deny_join_id0: {})",
            token, localAddr, remoteAddr, serverSide, denyJoinId0);
    }

    /// \brief Notification: An MPTCP connection has been established.
    virtual void mptcpConnectionEstablished(
        Token token, const generic::IPEndpoint& localAddr, const generic::IPEndpoint& remoteAddr,
        bool serverSide, bool denyJoinId0)
    {
        spdlog::debug("MPTCP[{:08x}]: Connection established", token);
    }

    /// \brief Notification: An MPTCP connection was closed.
    virtual void mptcpConnectionClosed(Token token)
    {
        spdlog::debug("MPTCP[{:08x}]: Connection closed", token);
    }

    /// \brief Notification: An address has been advertised by a peer.
    virtual void mptcpNewAddress(Token token, AddressId id, generic::IPEndpoint addr)
    {
        spdlog::debug("MPTCP[{:08x}]: New address {} (ID: {})", addr, id);
    }

    /// \brief Notification: An address is no longer advertised by a peer.
    virtual void mptcpAddressRemoved(Token token, AddressId id)
    {
        spdlog::debug("MPTCP[{:08x}]: Address {} removed", id);
    }

    /// \brief Notification: A new subflow was established.
    virtual void mptcpdNewSubflow(
        Token token, const generic::IPEndpoint& localAddr, const generic::IPEndpoint& remoteAddr,
        bool backup)
    {
        spdlog::debug("MPTCP[{:08x}]: New subflow {} -> {} (backup: {})",
            token, localAddr, remoteAddr, backup);
    }

    /// \brief Notification: A subflow was closed.
    virtual void mptcpSubflowClosed(
        Token token, const generic::IPEndpoint& localAddr, const generic::IPEndpoint& remoteAddr,
        bool backup, std::uint8_t error)
    {
        spdlog::debug("MPTCP[{:08x}]: Subflow closed {} -> {} (backup: {}, error: )",
            token, localAddr, remoteAddr, backup, error);
    }

    /// \brief Notification: Subflow priority changed.
    virtual void mptcpSubflowPriority(
        Token token, const generic::IPEndpoint& localAddr, const generic::IPEndpoint& remoteAddr,
        bool backup)
    {
        spdlog::debug("MPTCP[{:08x}]: Subflow priority changed {} -> {} (backup: {})",
            token, localAddr, remoteAddr, backup);
    }

    /// \brief Notification: MPTCP listener socket has been crated.
    virtual void mptcpListenerCreated(const generic::IPEndpoint& localAddr)
    {
        spdlog::debug("MPTCP[{:08x}]: Listener {} created", localAddr);
    }

    /// \brief Notification: MPTCP listener socket has been closed.
    virtual void mptcpListenerClosed(const generic::IPEndpoint& localAddr)
    {
        spdlog::debug("MPTCP[{:08x}]: Listener {} closed", localAddr);
    }

    /// Network Monitor Event Handlers ///

    /// \brief Notification: A new network interface is available.
    virtual void mptcpNewInterface(const Interface& iface)
    {
        spdlog::debug("MPTCP Interface Monitor: New interface {}", iface.name);
    }

    /// \brief Notification: Network interface flags were updated.
    virtual void mptcpUpdateInterface(const Interface& iface)
    {
        spdlog::debug("MPTCP Interface Monitor: Update interface {}", iface.name);
    }

    /// \brief Notification: A network interface was removed.
    virtual void mptcpDeleteInterface(const Interface& iface)
    {
        spdlog::debug("MPTCP Interface Monitor: Delete interface {}", iface.name);
    }

    /// \brief Notification: A new local network address is available.
    virtual void mptcpNewLocalAddress(const Interface& iface, const generic::IPAddress& addr)
    {
        spdlog::debug("MPTCP Interface Monitor: New local address {} on {}", addr , iface.name);
    }

    /// \brief Notification: A local network address was removed.
    virtual void mptcpDeleteLocalAddress(const Interface& iface, const generic::IPAddress& addr)
    {
        spdlog::debug("MPTCP Interface Monitor: Delete local address {} on {}", addr , iface.name);
    }

    /// Userspace Path Manager API Completion Callbacks ///

    virtual void mptcpPmReadyCompleted(TxID seq, int result)
    {
        spdlog::debug("MPTCP: PmReady returned {}", result);
    }

    virtual void mptcpPmAddAddrCompleted(
        TxID seq, int result, const generic::IPEndpoint& addr, AddressId id, Token token)
    {
        spdlog::debug("MPTCP[{:08x}]: PmAddAddr returned {}", token, result);
    }

    virtual void mptcpPmAddAddrNoListenerCompleted(
        TxID seq, int result, const generic::IPEndpoint& addr, AddressId id, Token token)
    {
        spdlog::debug("MPTCP[{:08x}]: PmAddAddrNoListener returned {}", token, result);
    }

    virtual void mptcpPmRemoveAddrCompleted(
        TxID seq, int result, const generic::IPEndpoint& addr, AddressId id, Token token)
    {
        spdlog::debug("MPTCP[{:08x}]: PmRemoveAddr returned {}", token, result);
    }

    virtual void mptcpPmAddSubflowCompleted(
        TxID seq, int result, Token token, AddressId localAddrId, AddressId remoteAddrId,
        const std::optional<generic::IPEndpoint>& localAddr, const generic::IPEndpoint& remoteAddr,
        bool backup)
    {
        spdlog::debug("MPTCP[{:08x}]: PmAddSubflow returned {}", token, result);
    }

    virtual void mptcpPmSetBackupCompleted(
        TxID seq, int result, Token token,
        const generic::IPEndpoint& localAddr, const generic::IPEndpoint& remoteAddr)
    {
        spdlog::debug("MPTCP[{:08x}]: PmSetBackup returned {}", token, result);
    }

    virtual void mptcpPmRemoveSubflowCompleted(
        TxID seq, int result, Token token,
        const generic::IPEndpoint& localAddr, const generic::IPEndpoint& remoteAddr)
    {
        spdlog::debug("MPTCP[{:08x}]: PmRemoveSubflow returned {}", token, result);
    }

    /// Kernel Path Manager APU Completion Callbacks ///

    virtual void mptcpKpmAddAddrCompleted(
        TxID seq, int result, const generic::IPEndpoint& addr,
        AddressId id, MpTcpFlags flags, int index)
    {
        spdlog::debug("MPTCP: KpmAddAddr returned {}", result);
    }

    virtual void mptcpKpmRemoveAddrCompleted(TxID seq, int result, AddressId id)
    {
        spdlog::debug("MPTCP: KpmRemoveAdd returned {}", result);
    }

    virtual void mptcpKpmGetAddrCompleted(
        TxID seq, int result, const AddrInfo& addrinfo, AddressId id) {}
    virtual void mptcpKpmDumpAddrsCompleted(
        TxID seq, int result, std::span<const AddrInfo> addrinfo) {}
    virtual void mptcpKpmFlushAddrsCompleted(TxID seq, int result) {}

    virtual void mptcpKpmSetLimitsCompleted(
        TxID seq, int result, std::span<const MpTcpLimit> limits)
    {
        spdlog::debug("MPTCP: KpmSetLimits returned {}", result);
    }

    virtual void mptcpKpmGetLimitsCompleted(
        TxID seq, int result, std::span<const MpTcpLimit> limits) {}
    virtual void mptcpKpmSetFlagsCompleted(
        TxID seq, int result, const generic::IPEndpoint& addr, MpTcpFlags flags) {}

    friend class PathManager;
};

/// \brief Connection to the userspace path manager for MPTCP.
///
/// TODO
class PathManager
{
private:
    IpcChannel m_ipc;
    std::string socketPath;
    PathManagerCallbacks* callbacks = nullptr;
    std::atomic<TxID> m_seq = 0; // atomic?
    static const std::uint32_t IPC_MAGIC = 0x77846780; // MTCP

public:
    template <typename Executor>
    PathManager(Executor& ex, const std::string& socketPath)
        : m_ipc(ex, IPC_MAGIC), socketPath(socketPath)
    {}

    std::error_code connect()
    {
        spdlog::info("Connection to mptcpd Scitra plugin at {}", socketPath);
        auto ec = m_ipc.connect(socketPath);
        if (ec) {
            spdlog::error("Failed to connect to '{}': {} MPTCP path manager will not be available.",
                socketPath, ec.message());
        }
        return ec;
    }

    void disconnect() { m_ipc.close(); }
    bool isConnected() const { return m_ipc.isOpen(); }

    boost::asio::awaitable<std::error_code> waitForMessages()
    {
        std::vector<std::byte> buf(1024);
        while (m_ipc.isOpen()) {
            auto [msgBuf, func, seq, ec] = co_await m_ipc.receive(buf);
            if (ec) {
                spdlog::error("Reading from mptcpd plugin failed: {} Disconnected.", ec.message());
                disconnect();
                co_return ec;
            }
            if (callbacks) dispatchMessage(static_cast<Function>(func), seq, buf);
        }
        co_return ErrorCode::Cancelled;
    }

    /// \brief Check if mptcpd path manager is ready to user.
    Maybe<TxID> PmIsReady();

    /// \brief Advertise new network address to peers.
    Maybe<TxID> PmAddAddr(const generic::IPEndpoint& addr, AddressId id, Token token);

    /// \brief Advertise new network address to peers without creating a listener.
    Maybe<TxID> PmAddAddrNoListener(const generic::IPEndpoint& addr, AddressId id, Token token);

    /// \brief Stop advertising a network address.
    Maybe<TxID> PmRemoveAddr(const generic::IPEndpoint& addr, AddressId id, Token token);

    /// \brief Create a new subflow.
    Maybe<TxID> PmAddSubflow(
        Token token,
        AddressId localAddrId,
        AddressId remoteAddrId,
        const std::optional<generic::IPEndpoint>& localAddr,
        const generic::IPEndpoint& remoteAddr,
        bool backup);

    /// \brief Set priority of a subflow.
    Maybe<TxID> PmSetBackup(
        Token token,
        const generic::IPEndpoint& localAddr,
        const generic::IPEndpoint& remoteAddr,
        bool backup);

    /// \brief Remove a subflow.
    Maybe<TxID> PmRemoveSubflow(
        Token token,
        const generic::IPEndpoint& localAddr,
        const generic::IPEndpoint& remoteAddr);

    /// \brief Kernel Path Manager: Advertise new network address to peers.
    Maybe<TxID> KpmAddAddr(
        const generic::IPEndpoint& addr,
        AddressId id,
        MpTcpFlags flags,
        int index);

    /// \brief Kernel Path Manager: Stop advertising a network address.
    Maybe<TxID> KpmRemoveAddr(AddressId id);

    /// \brief Kernel Path Manager: Get network address corresponding to address ID.
    Maybe<TxID> KpmGetAddr(AddressId id);

    /// \brief Kernel Path Manager: Get list of MPTCP network addresses.
    Maybe<TxID> KpmDumpAddrs();

    /// \brief Kernel Path Manager: Flush MPTCP addresses.
    Maybe<TxID> KpmFlushAddrs();

    /// \brief Kernel Path Manager: Set MPTCP resource limits.
    Maybe<TxID> KpmSetLimits(std::span<MpTcpLimit> limits);

    /// \brief Kernel Path Manager: Get MPTCP resource limits.
    Maybe<TxID> KpmGetLimits();

    /// \brief Kernel Path Manager: Set MPTCP resource limits.
    Maybe<TxID> KpmSetFlags(const generic::IPEndpoint& addr, MpTcpFlags flags);

private:
    void dispatchMessage(Function func, TxID seq, std::span<std::byte> raw);
};

} // namespace mptcpd
} // namespace scitra
} // namespace scion
