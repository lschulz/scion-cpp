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

#include "scion/path_selector.h"


#if __cplusplus
extern "C" {
#endif

void scion_sel_initialize(const char* executable, const char* args);
size_t scion_sel_filter(uint64_t destination, scion_path** paths, size_t pathLen);
void* scion_sel_notify_created(scion_native_handle socket, int type, int protocol);
void scion_sel_notify_close(void* ctx, scion_native_handle socket);
void scion_sel_notify_bind(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* addr);
void scion_sel_notify_connect(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* addr);
void scion_sel_notify_received(void* ctx, scion_native_handle socket,
    struct scion_sel_packet_info* pkt);
bool scion_sel_select_cached(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* to, scion_path* path,
    const uint8_t* payload, size_t payload_len);
scion_path* scion_sel_select(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* to, scion_path** paths, size_t paths_len,
    const uint8_t* payload, size_t payload_len);

#if __cplusplus
} // extern "C"
#endif
