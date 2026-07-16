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

#include <ell/ell.h>
#include <mptcpd/plugin.h>
#include "plugin.h"

static const char* SCITRA_MPTCP_PM_SOCKET = "/run/shm/scitra-mptcpd";

static const struct mptcpd_plugin_ops pm_ops = {
    .new_connection = NEW_CONNECTION,
    .connection_established = CONNECTION_ESTABLISHED,
    .connection_closed = CONNECTION_CLOSED,
    .new_address = NEW_ADDRESS,
    .address_removed = ADDRESS_REMOVED,
    .new_subflow = NEW_SUBFLOW,
    .subflow_closed = SUBFLOW_CLOSED,
    .subflow_priority = SUBFLOW_PRIORITY,
    .listener_created = LISTENER_CREATED,
    .listener_closed = LISTENER_CLOSED,
    .new_interface = NEW_INTERFACE,
    .update_interface = UPDATE_INTERFACE,
    .delete_interface = DELETE_INTERFACE,
    .new_local_address = NEW_LOCAL_ADDRESS,
    .delete_local_address = DELETE_LOCAL_ADDRESS
};

#define PLUGIN_INIT CONCAT(PLUGIN_NAME, _init)
static int PLUGIN_INIT(struct mptcpd_pm* pm)
{
    static const char name[] = L_STRINGIFY(PLUGIN_NAME);
    const char* socket_path = getenv("SCITRA_MPTCP_PM_SOCKET");
    if (!socket_path) socket_path = SCITRA_MPTCP_PM_SOCKET;

    if (!mptcpd_plugin_register_ops(name, &pm_ops)) {
        l_error("Failed to initialize Scitra path manager plugin.");
        return -1;
    }

    int err = spawn_ipc_thread(pm, socket_path);
    if (err) return err;

    l_info("Scitra path manager initialized.");
    return 0;
}

#define PLUGIN_EXIT CONCAT(PLUGIN_NAME, _exit)
static void PLUGIN_EXIT(struct mptcpd_pm* pm)
{
    stop_and_join_ipc_thread();
    l_info("Scitra path manager exited.");
}

MPTCPD_PLUGIN_DEFINE(
    PLUGIN_NAME,
    PLUGIN_DESC,
    MPTCPD_PLUGIN_PRIORITY_HIGH,
    &PLUGIN_INIT,
    &PLUGIN_EXIT
)
