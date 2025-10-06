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

#include "interposer.h"
#include "scion/posix/underlay.hpp"


// RAII wrapper that ensures sockets are closed when tests complete.
class SocketWrapper
{
private:
    NativeSocket socket = scion::posix::INVALID_SOCKET_VALUE;

public:
    SocketWrapper() = default;
    explicit SocketWrapper(NativeSocket socket)
        : socket(socket)
    {}

    SocketWrapper(const SocketWrapper&) noexcept = delete;
    SocketWrapper(SocketWrapper&& other) noexcept
        : socket(other.socket)
    {
        other.socket = scion::posix::INVALID_SOCKET_VALUE;
    }

    SocketWrapper& operator=(const SocketWrapper&) noexcept = delete;
    SocketWrapper& operator=(SocketWrapper&& other) noexcept
    {
        swap(*this, other);
        return *this;
    }

    friend void swap(SocketWrapper& a, SocketWrapper& b)
    {
        std::swap(a.socket, b.socket);
    }

    ~SocketWrapper()
    {
        close();
    }

    void close()
    {
        if (socket != scion::posix::INVALID_SOCKET_VALUE) {
            interposer_close(socket);
            socket = scion::posix::INVALID_SOCKET_VALUE;
        }
    }

    NativeSocket operator*() const { return socket; }
};
