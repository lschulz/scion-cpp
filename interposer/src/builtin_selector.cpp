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

#include "builtin_selector.h"

#include <boost/circular_buffer.hpp>

#include <algorithm>
#include <chrono>
#include <unordered_map>
#include <utility>

using std::uint64_t;


// Number of clients the path selector remembers.
static size_t CLIENT_CAPACITY = 32;

struct State
{
    // Socket type (SOCK_STREAM or SOCK_DGRAM)
    const int type;
    // Whether the socket is considered passive (listening for and responding to
    // packets from clients) or active (initiating a connecting to another
    // socket). Passive sockets try to answer on the same path they previously
    // have received something on.
    bool isPassive = false;
    // Client: Last path selected to a particular destination ISD-ASN
    std::unordered_map<uint64_t, scion_digest> lastSelected;
    // Server: Last path used by clients. Buffer with fixed capacity, new
    // clients evict clients we have not received anything from for some time.
    boost::circular_buffer<std::pair<sockaddr_scion, scion_digest>> clients;

    State(int type)
        : type(type)
    {}
};

bool operator==(const sockaddr_scion& a, const sockaddr_scion& b)
{
    return scion_sockaddr_are_equal(&a, &b);
}

// Find the first path that matches the given path digest. Returns paths_len if
// no such path exists.
size_t find_path(scion_path** paths, size_t paths_len, scion_digest& digest);

extern "C"
void scion_sel_initialize(const char* executable, const char* args)
{
}

extern "C"
size_t scion_sel_filter(uint64_t destination, scion_path** paths, size_t paths_len)
{
    return paths_len;
}

extern "C"
void* scion_sel_notify_created(scion_native_handle socket, int type, int protocol)
{
    return new State(type);
}

extern "C"
void scion_sel_notify_close(void* ctx, scion_native_handle socket)
{
    delete reinterpret_cast<State*>(ctx);
}

extern "C"
void scion_sel_notify_bind(
    void* ctx, scion_native_handle socket, const struct sockaddr_scion* addr)
{
}

extern "C"
void scion_sel_notify_connect(
    void* ctx, scion_native_handle socket, const struct sockaddr_scion* addr)
{
    auto state = reinterpret_cast<State*>(ctx);
    if (!state) return;
    state->isPassive = false;
    state->lastSelected.clear();
    state->clients.rset_capacity(0);
}

extern "C"
void scion_sel_notify_received(
    void* ctx, scion_native_handle socket, struct scion_sel_packet_info* pkt)
{
    auto state = reinterpret_cast<State*>(ctx);
    if (!state) return;

    // Connected sockets actively select their own paths without regard for the
    // paths selected by the remote host.
    if (!state->isPassive) return;

    // Reverse the path before getting the digest, so all recorded paths start
    // from this socket.
    if (scion_raw_path_reverse(pkt->path)) return;
    scion_digest digest;
    scion_raw_path_digest(pkt->path, &digest);

    // Record the path digest in the ringbuffer
    if (state->clients.capacity() == 0) {
        state->clients.rset_capacity(CLIENT_CAPACITY);
    }
    auto i = std::ranges::find(state->clients, *pkt->from, [] (auto& x) -> sockaddr_scion& {
        return x.first;
    });
    if (i != state->clients.end()) {
        i->second = digest;
    } else {
        state->clients.push_back({*pkt->from, digest});
    }
}

extern "C"
bool scion_sel_select_cached(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* to, scion_path* path,
    const uint8_t* payload, size_t payload_len)
{
    using namespace std::chrono;
    // Reuse previous path if not broken or expired.
    if (scion_path_broken(path)) return false;
    auto now = duration_cast<nanoseconds>(utc_clock::now().time_since_epoch()).count();
    if (scion_path_expiry(path) <= (uint64_t)now) return false;
    return true;
}

extern "C"
scion_path* scion_sel_select(void* ctx, scion_native_handle socket,
    const struct sockaddr_scion* to, scion_path** paths, size_t paths_len,
    const uint8_t* payload, size_t payload_len)
{
    auto state = reinterpret_cast<State*>(ctx);
    if (state->isPassive) {
        // Prefer to use the last path used by the client.
        auto i = std::ranges::find(state->clients, *to, [] (auto& x) -> sockaddr_scion& {
            return x.first;
        });
        if (i != state->clients.end()) {
            auto path = find_path(paths, paths_len, i->second);
            if (path < paths_len) {
                if (!scion_path_broken(paths[path])) {
                    return paths[path];
                }
            }
        }
    }

    // Repeat the last selection if the path is still available.
    auto i = state->lastSelected.find(to->sscion_addr.sscion_isd_asn);
    if (i != state->lastSelected.end()) {
        auto path = find_path(paths, paths_len, i->second);
        if (path < paths_len) {
            if (!scion_path_broken(paths[path])) {
                return paths[path];
            }
        }
    }

    // Select the first path that is not broken.
    for (size_t i = 0; i < paths_len; ++i) {
        if (!scion_path_broken(paths[i])) {
            scion_digest digest;
            scion_path_digest(paths[i], &digest);
            state->lastSelected[to->sscion_addr.sscion_isd_asn] = digest;
            return paths[i];
        }
    }

    return nullptr;
}

size_t find_path(scion_path** paths, size_t paths_len, scion_digest& digest)
{
    scion_digest path_digest;
    for (size_t i = 0; i < paths_len; ++i) {
        scion_path_digest(paths[i], &path_digest);
        if (SCION_DIGEST_EQUAL(path_digest, digest))
            return i;
    }
    return paths_len;
}
