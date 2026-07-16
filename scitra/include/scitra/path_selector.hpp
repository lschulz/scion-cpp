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

#include "scion/path/path.hpp"
#include "scitra/path_manager.hpp"
#include "scitra/scitra-tun/flow.hpp"

#include <vector>


namespace scion { // TODO: Drop outer scion namespace
namespace scitra {

typedef void (*NewConnectionCB)(mptcpd::Token, generic::IPEndpoint, generic::IPEndpoint);
typedef void (*PmAddAddrCompleted)(const mptcpd::msg::PmAddAddr&, std::uint32_t);

class LoadablePathSelector : public mptcpd::PathManagerCallbacks
{
private:
    NewConnectionCB newConnection = nullptr;

public:
    bool modifyPath(const FlowID& flowid, std::uint8_t t, PathPtr currentPath)
    {
    }

    Maybe<PathPtr> selectPath(const FlowID& flowid, std::uint8_t tc, std::vector<PathPtr>& paths)
    {
    }

    Maybe<PathPtr> selectPath2(const FlowID& flowid, std::uint8_t tc, PathPtr currentPath)
    {
        // Keep currentPath
        // or call queryPaths and decide on a new one
    }

    Maybe<PathPtr> selectPathMulti(const FlowID& flowid, std::uint8_t tc, std::vector<PathPtr>& others)
    {
    }

private:
    // TODO: Map to a C interface
    virtual void newConnection(
        mptcpd::Token token, generic::IPEndpoint localAddr, generic::IPEndpoint remoteAddr)
    {
        if (newConnection) newConnection(token, localAddr, remoteAddr);
    }

    virtual void pmAddAddrCompleted(
        generic::IPEndpoint addr, mptcpd::AddressId id, mptcpd::Token token, int result
    )
    {
    }
};

} // namespace scitra
} // namespace scion
