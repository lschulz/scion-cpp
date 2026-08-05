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

#include "scitra/scitra-tun/service.hpp"
#include <systemd/sd-daemon.h>
#include <mutex>

/// \file Service management for running as a daemon controlled by systemd.

namespace service {

static std::mutex g_mutex;
static bool g_isService = false;

void setRunningAsService()
{
    std::unique_lock<std::mutex> lock(g_mutex);
    g_isService = true;
}

void setServiceStatus(Status status)
{
    std::unique_lock<std::mutex> lock(g_mutex);
    if (g_isService) {
        switch (status) {
        case Status::Running:
        case Status::ReloadCompleted:
            sd_notify(0, "READY=1");
            break;
        case Status::Reloading:
            sd_notify(0, "RELOADING=1");
            break;
        case Status::StopPending:
            sd_notify(0, "STOPPING=1");
            break;
        default:
            break;
        }
    }
}

} // namespace service
