#pragma once


/// \brief Platform-independent functions for communicating service status to
/// the OS.
/// \warning Call these functions only after main has begun execution, not
/// during global initialization.
namespace service {

enum class Status
{
    Running,
    Reloading,
    ReloadCompleted,
    StopPending,
    Stopped,
};

/// \brief Calling this function enables the service lifecycle management
/// functions in the service namespace.
void setRunningAsService();

/// \brief Notify the OS of current status when running as a daemon or Windows
/// service.
///
/// Calls sd_notify() on Linux and BSD. Calls SetServiceStatus() on Windows.
/// Ignored ifScitra was not started with the `--daemon` or `-service`
/// option.
void setServiceStatus(Status status);

} // namespace service
