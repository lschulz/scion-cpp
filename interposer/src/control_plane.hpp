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

#include "log.h"
#include "scion/daemon/client.hpp"

#include <netinet/ip.h>

#include <string_view>

class Interposer;


// Interface providing information that must be retrieved from an external service.
class ControlPlane
{
public:
    virtual ~ControlPlane() = default;
    virtual bool isConnected() const = 0;
    virtual int internalAddrFamily() const = 0;
    virtual const scion::daemon::AsInfo& asInfo() const = 0;
    virtual scion::daemon::PortRange dispatchedPorts() const = 0;
    virtual std::error_code queryPaths(scion::IsdAsn src, scion::IsdAsn dst,
        std::vector<scion::PathPtr>& paths) const = 0;

private:
    virtual bool connect(const std::string& daemonAddress) = 0;
};

#if TESTING
// Dummy control plane for unit tests.
class TestCP : public ControlPlane
{
private:
    virtual bool connect(const std::string& daemonAddress) override
    {
        return true;
    }

public:
    virtual bool isConnected() const override
    {
        return true;
    }

    virtual int internalAddrFamily() const override
    {
        return AF_INET;
    }

    virtual const scion::daemon::AsInfo& asInfo() const override
    {
        using namespace scion;
        static daemon::AsInfo asInfo = {
            .isdAsn = IsdAsn(Isd(1), Asn(64496)),
            .core = false,
            .mtu = 1400,
        };
        return asInfo;
    }

    virtual scion::daemon::PortRange dispatchedPorts() const override
    {
        return scion::daemon::PortRange(31000, 32767);
    }

    virtual std::error_code queryPaths(scion::IsdAsn src, scion::IsdAsn dst,
        std::vector<scion::PathPtr>& paths) const override
    {
        paths.clear();
        return grpc::StatusCode::OK;
    }
};
#endif

// Provides AS information and services by connecting to a local SCION daemon.
class DaemonConn : public ControlPlane
{
private:
    std::unique_ptr<scion::daemon::GrpcDaemonClient> daemonClient;
    int addrFamily = 0;
    scion::daemon::AsInfo info;
    scion::daemon::PortRange portRange;

private:
    friend class Interposer;
    virtual bool connect(const std::string& daemonAddress) override;

public:
    virtual bool isConnected() const override { return daemonClient != nullptr; }
    virtual int internalAddrFamily() const override { return addrFamily; }
    virtual const scion::daemon::AsInfo& asInfo() const override { return info; }
    virtual scion::daemon::PortRange dispatchedPorts() const override { return portRange; }

    virtual std::error_code queryPaths(scion::IsdAsn src, scion::IsdAsn dst,
        std::vector<scion::PathPtr>& paths) const override
    {
        using namespace scion;
        using namespace scion::daemon;
        paths.clear();
        if (daemonClient) {
            auto flags = PathReqFlags::Refresh | PathReqFlags::AllMetadata;
            return daemonClient->rpcPaths(info.isdAsn, dst, flags, std::back_inserter(paths));
        }
        return grpc::StatusCode::UNAVAILABLE;
    }
};
