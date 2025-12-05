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

#if _WIN32
#include <Winsock2.h>
#else
#include <sys/socket.h>
#endif


namespace scion {

/// \brief Flags that can be passed to the send* and recv* methods of SCION
/// sockets. Some flags correspond to MSG_* flags in the POSIX or OS-specific
/// socket API and can be cast to MsgFlags directly. Other flags are
/// SCION-specific.
enum MsgFlags
{
    /// \brief Empty set of flags.
    SMSG_NO_FLAGS = 0,

#ifdef _WIN32
    SMSG_DONTWAIT = 0,
#else
    /// \brief Enable nonblocking IO. Equivalent to MSG_DONTWAIT. Not supported
    /// on Windows.
    SMSG_DONTWAIT = MSG_DONTWAIT,
#endif

    /// \brief Return data without removing it from the receive buffer.
    /// Equivalent to MSG_PEEK.
    SMSG_PEEK = MSG_PEEK,

    /// \brief Wait until the full request is satisfied. Equivalent to
    /// MSG_WAITALL.
    SMSG_WAITALL = MSG_WAITALL,

#ifdef _WIN32
    SMSG_CONFIRM = 0,
#else
    /// \brief Confirm to link layer that forward progress happened. Only useful
    /// for UDP sockets and not used in Windows.
    SMSG_CONFIRM = MSG_CONFIRM,
#endif

#ifdef _WIN32
    // There are no signals in Windows.
    SMSG_NOSIGNAL = 0,
#else
    /// \brief Do not generate SIGPIPE on stream oriented sockets when the
    /// remote end breaks the connection.
    SMSG_NOSIGNAL = MSG_NOSIGNAL,
#endif

    /// \brief Return immediately if an SCMP message has been received instead
    /// of waiting for more data.
    SMSG_RECV_SCMP = 0x10'0000,

    /// \brief Return immediately if a STUN packet has been received instead of
    /// waiting for more data.
    SMSG_RECV_STUN = 0x20'0000,
};

/// \brief Combination of all SCION-specific flags MsgFlags.
constexpr int SMSG_SCION_ALL = SMSG_RECV_SCMP | SMSG_RECV_STUN;

} // namespace scion
