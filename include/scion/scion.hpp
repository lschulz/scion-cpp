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

/// \file
/// \brief Main include file for SCION-CPP with the POSIX backend.

#pragma once

#include <scion/error_codes.hpp>

#include <scion/addr/isd_asn.hpp>
#include <scion/addr/address.hpp>
#include <scion/addr/endpoint.hpp>
#include <scion/addr/generic_ip.hpp>

#include <scion/daemon/client.hpp>
#include <scion/drkey/drkey.hpp>

#include <scion/extensions/idint.hpp>

#include <scion/path/attributes.hpp>
#include <scion/path/path_meta.hpp>
#include <scion/path/digest.hpp>
#include <scion/path/decoded_scion.hpp>
#include <scion/path/raw.hpp>
#include <scion/path/path.hpp>

#include <scion/path/cache.hpp>
#include <scion/path/shared_cache.hpp>

#include <scion/scmp/handler.hpp>
#include <scion/scmp/path_mtu.hpp>

#include <scion/posix/scmp_socket.hpp>
#include <scion/posix/udp_socket.hpp>
