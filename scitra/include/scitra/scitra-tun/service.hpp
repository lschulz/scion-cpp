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
