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
#include "scion/addr/address.hpp"
#include "scion/addr/generic_ip.hpp"

#include <string>
#include <utility>
#include <vector>


enum class AddressMode
{
    NATIVE_SCION,
    ADDRESS_MAPPING,
};

// Interposer configuration options
struct Options
{
    // Full path to the executable image (may be overridden by user)
    std::string executable;
    // Log verbosity
    int logLevel = LEVEL_WARN;

    // Default representation of SCION addresses
    AddressMode addressMode = AddressMode::ADDRESS_MAPPING;
    // Enable support for SCION-mapped IPv6 addresses and surrogate addresses
    // in getnameinfo, inet_pton, and inet_ntop.
    bool extendedAddressMapping = true;
    // Promote unconnected UDP sockets when sending to a SCION address for the
    // first time.
    bool allowPromoteOnSendTo = false;

    // Default IP address to be used with SCION if the socket is bound to a
    // wildcard IP.
    std::optional<scion::generic::IPAddress> defaultIPv4;
    std::optional<scion::generic::IPAddress> defaultIPv6;

    // Predefined surrogate addresses
    using SurrogateAddresses = std::vector<std::pair<scion::generic::IPAddress, scion::ScIPAddress>>;
    SurrogateAddresses surrogates;

    // Path to a shared library from which to load the path selector.
    // If empty, the built-in path selector is used.
    std::string pathSelector;
    // Arguments passed to the path selector
    std::string selectorArgs;

    // Whether to use an external SCION daemon
    bool connectToDaemon = true;
    // IP address and port of the SCION daemon
    std::string daemonAddress = "127.0.0.1:30255";
};

// Load interposer configuration.
void loadOptions(Options& opts);
