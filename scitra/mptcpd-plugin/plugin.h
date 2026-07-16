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

#include <mptcpd/path_manager.h>

#define PLUGIN_NAME scitra
#define PLUGIN_DESC "This plugin allows Scitra-TUN to control MPTCP subflow creation."

#define CONCAT2(a, b) a ## b
#define CONCAT(a, b) CONCAT2(a, b)

int spawn_ipc_thread(struct mptcpd_pm* pm, const char* bind);
void stop_and_join_ipc_thread();

#define NEW_CONNECTION CONCAT(PLUGIN_NAME, _new_connection)
void NEW_CONNECTION(mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool server_side,
    bool deny_join_id0,
    struct mptcpd_pm* pm);

#define CONNECTION_ESTABLISHED CONCAT(PLUGIN_NAME, _connection_established)
void CONNECTION_ESTABLISHED(mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool server_side,
    bool deny_join_id0,
    struct mptcpd_pm* pm);

#define CONNECTION_CLOSED CONCAT(PLUGIN_NAME, _connection_closed)
void CONNECTION_CLOSED(mptcpd_token_t token, struct mptcpd_pm* pm);

#define NEW_ADDRESS CONCAT(PLUGIN_NAME, _new_address)
void NEW_ADDRESS(mptcpd_token_t token,
    mptcpd_aid_t id,
    const struct sockaddr* addr,
    struct mptcpd_pm* pm);

#define ADDRESS_REMOVED CONCAT(PLUGIN_NAME, _address_removed)
void ADDRESS_REMOVED(mptcpd_token_t token,
    mptcpd_aid_t id,
    struct mptcpd_pm* pm);

#define NEW_SUBFLOW CONCAT(PLUGIN_NAME, _new_subflow)
void NEW_SUBFLOW(mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool backup,
    struct mptcpd_pm* pm);

#define SUBFLOW_CLOSED CONCAT(PLUGIN_NAME, _subflow_closed)
void SUBFLOW_CLOSED(mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool backup,
    uint8_t error,
    struct mptcpd_pm* pm);

#define SUBFLOW_PRIORITY CONCAT(PLUGIN_NAME, _subflow_priority)
void SUBFLOW_PRIORITY(mptcpd_token_t token,
    const struct sockaddr* laddr,
    const struct sockaddr* raddr,
    bool backup,
    struct mptcpd_pm* pm);

#define LISTENER_CREATED CONCAT(PLUGIN_NAME, _listener_created)
void LISTENER_CREATED(const struct sockaddr* laddr,
    struct mptcpd_pm* pm);

#define LISTENER_CLOSED CONCAT(PLUGIN_NAME, _listener_closed)
void LISTENER_CLOSED(const struct sockaddr* laddr,
    struct mptcpd_pm* pm);

#define NEW_INTERFACE CONCAT(PLUGIN_NAME, _new_interface)
void NEW_INTERFACE(const struct mptcpd_interface* i,
    struct mptcpd_pm* pm);

#define UPDATE_INTERFACE CONCAT(PLUGIN_NAME, _update_interface)
void UPDATE_INTERFACE(const struct mptcpd_interface* i,
    struct mptcpd_pm* pm);

#define DELETE_INTERFACE CONCAT(PLUGIN_NAME, _delete_interface)
void DELETE_INTERFACE(const struct mptcpd_interface* i,
    struct mptcpd_pm* pm);

#define NEW_LOCAL_ADDRESS CONCAT(PLUGIN_NAME, _new_local_address)
void NEW_LOCAL_ADDRESS(const struct mptcpd_interface* i,
    const struct sockaddr* sa,
    struct mptcpd_pm* pm);

#define DELETE_LOCAL_ADDRESS CONCAT(PLUGIN_NAME, _delete_local_address)
void DELETE_LOCAL_ADDRESS(const struct mptcpd_interface* i,
    const struct sockaddr* sa,
    struct mptcpd_pm* pm);
