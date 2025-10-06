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

#include "scion/scion.h"
#include <stdint.h>

/// \file path_selector.h
/// \brief Interface for a SCION interposer path selector.
///
/// The path selector may be called concurrently from multiple threads, but
/// calls pertaining to the same socket (with the same socket handle) are
/// sequential and do not require additional synchronization.

/// Called to initialize the path selector before any other callback.
/// `executable` is the full path to the executable hosting the interposer.
/// `args` are user supplied arguments to the path selector.
typedef void (*scion_sel_initialize_t)(const char* executable, const char* args);

/// Global path filter callback. Invoked when a path lookup is made to filter
/// which of the paths are going to be presented to the path scheduler.
///
/// `paths_len` paths to ISD-ASN `destination` are presented to the policy in an
/// array pointed to by `paths`. The policy may remove or reorder path in the
/// array (but not duplicate paths) and return the resulting new length of the
/// array.
///
/// The policy must not store any of the path pointers, as they may be invalided
/// after the callback returns.
typedef size_t (*scion_sel_filter_t)(uint64_t destination, scion_path** paths, size_t paths_len);

/// Callback notifying the path selector of a new SCION socket.
typedef void* (*scion_sel_notify_created_t)(scion_native_handle socket, int type, int protocol);

/// Callback notifying the path selector that a socket is about to be closed.
/// The packet selector should consider the socket handle invalid once this
/// function returns.
typedef void (*scion_sel_notify_close_t)(void* ctx, scion_native_handle socket);

/// Callback notifying the path selector that a socket has been bound to the
/// local address `addr`.
typedef void (*scion_sel_notify_bind_t)(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* addr);

/// Callback notifying the path selector that a socket has been connected to
/// a remote host at `addr`.
typedef void (*scion_sel_notify_connect_t)(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* addr);

struct scion_sel_packet_info
{
    const struct sockaddr_scion* from;
    scion_raw_path* path;
    struct sockaddr* underlay;
    socklen_t underlay_len;
    const uint8_t* payload;
    size_t payload_len;
};

/// Called when a packet has been received.
typedef void (*scion_sel_notify_received_t)(
    void* ctx, scion_native_handle socket, struct scion_sel_packet_info* info);

/// Called when a socket is sending a packet to a destination it already has a
/// cached path for.
///
/// `to` is the destination host and `path` the cached path. The payload of the
/// packet about to be sent to is given in by `payload` with a length of
/// `payload_len` bytes.
///
/// By returning true, the selector indicates that the cached path should be
/// reused. If the selector returns false, the cache is invalidated and
/// path_select is invoked to select a new path.
typedef bool (*scion_sel_select_cached_t)(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* to, scion_path* path,
    const uint8_t* payload, size_t payload_len);

/// Request a path for sending a a single packet on `socket` to the destination
/// `to`.
///
/// Available paths are given in the array pointed to by `paths` with a length
/// of `paths_len`. `paths_len` is guaranteed to be at least one. The payload of
/// the packet about to be sent to is given in by `payload` with a length of
/// `payload_len` bytes.
///
/// The selector should return one of the paths from `paths`. Path pointers must
/// not be stored as they may be invalidated after the function returned. Paths
/// should instead be identified by comparing path hashes. If the selector
/// nothing is sent and the the send function returns with an error.
typedef scion_path* (*scion_sel_select_t)(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* to, scion_path** paths, size_t paths_len,
    const uint8_t* payload, size_t payload_len);
