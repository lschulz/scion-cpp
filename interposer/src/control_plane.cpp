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

#include "control_plane.hpp"
#include "interposer.hpp"
#include "log.h"


bool DaemonConn::connect(const std::string& daemonAddress)
{
    using namespace scion;

    auto client = std::make_unique<scion::daemon::GrpcDaemonClient>(daemonAddress);

    // Figure out the AS' underlay address type by looking at the service addresses
    std::vector<std::pair<std::string, std::string>> services;
    if (auto ec = client->rpcServices(std::back_inserter(services)); !ec) {
        if (!services.empty()) {
            auto ep = generic::IPEndpoint::Parse(services.front().second);
            if (ep.has_value())
            addrFamily = ep->host().is4() ? AF_INET : AF_INET6;
        }
    } else {
        interposer_log(LEVEL_ERROR, "Error connecting to SCION daemon: %s",
            scion::fmtError(ec).c_str());
        return false;
    }

    // Basic AS info
    if (auto asInfo = client->rpcAsInfo(scion::IsdAsn()); asInfo.has_value()) {
        info = *asInfo;
    } else {
        interposer_log(LEVEL_ERROR, "Error connecting to SCION daemon: %s",
            scion::fmtError(asInfo.error()).c_str());
        return false;
    }

    // Dispatched port range
    if (auto ports = client->rpcPortRange(); ports.has_value()) {
        portRange = *ports;
    } else {
        interposer_log(LEVEL_ERROR, "Error connecting to SCION daemon: %s",
            scion::fmtError(ports.error()).c_str());
        return false;
    }

    daemonClient = std::move(client);
    return true;
}
