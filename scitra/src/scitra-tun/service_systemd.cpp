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
