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

/// \page c-interface C Interface
///
/// The header scion.h provides a C interface to SCION-CPP.
///
/// The sockets exposed by the C interface are based on scion::asio::UDPSocket.
/// TCP is not implemented yet. Both synchronous and asynchronous socket
/// operations are exposed. Asynchronous operations notify the application of
/// I/O completion via callback functions with a user-supplied void pointer as
/// context. In addition to the SCION socket, some additional ASIO classes like
/// timers are exposed in the C API to support development of asynchronous SCION
/// applications in C.
///
/// In order to use the C interface. an application must first create a host
/// context with scion_create_host_context(). I/O related library objects store
/// pointers to the host context, so the context must remain valid and fixed in
/// memory for the entire lifetime of objects created from it. The host context
/// also contains the ASIO event loop which may be controlled using the
/// functions scion_poll(), scion_run(), scion_run_for(), scion_stop(), and
/// scion_restart().
///
/// ### Name Resolution ###
/// SCION name resolution is supported with a synchronous and asynchronous
/// interface through scion_resolve_name() and scion_resolve_name_async(). As in
/// SCION-CPP, a c-ares background thread carries out the actual DNS requests to
/// the systems default resolver, however callbacks are always executed in the
/// application's own threads.
///
/// ### Path Lookup ###
/// SCION path lookup is available as the blocking function scion_query_paths().
/// Asynchronous path lookups are not exposed, as gRPC requires it's own
/// separate event loop which is not provided by the C interface yet.
///
/// ### Socket Addresses ###
/// The API represents SCION addresses as scion_addr structs which contain the
/// ISD-ASN and host address. Socket addresses are stored in sockaddr_scion
/// struct that are analogous to sockaddr_in and sockaddr_in6 for IPv4 and IPv6
/// sockets. The API uses the address family AF_SCION to distinguish SCION
/// addresses from IP. Since AF_SCION is not part of the POSIX socket
/// specification, an arbitrarily chosen integer is assigned to it. If
/// necessary, the preprocessor macro AF_SCION can be set to a different unused
/// value without affecting the library or compatibility with other SCION
/// applications.
///
/// ### Examples ###
/// * \ref examples/c/echo_udp/main.c
/// * \ref examples/c/echo_udp_async/main.c

/// \file
/// \brief See \ref c-interface

#pragma once

#include <stdbool.h>
#include <stdint.h>

#if _WIN32
#include <Winsock2.h>
#include <WS2tcpip.h>
#undef interface
#else
#include <netinet/in.h>
#endif

#ifdef __cplusplus
#include <type_traits>
#endif

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

/// \brief SCION address family used in the pseudo-POSIX sockaddr structs.
#define AF_SCION 64

/// \brief 8 byte host to network byte order.
inline uint64_t scion_htonll(uint64_t x)
{
#if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_LITTLE__
    return ((x & 0x00000000000000ffull) << 56)
        | ((x & 0x000000000000ff00ull) << 40)
        | ((x & 0x0000000000ff0000ull) << 24)
        | ((x & 0x00000000ff000000ull) << 8)
        | ((x & 0x000000ff00000000ull) >> 8)
        | ((x & 0x0000ff0000000000ull) >> 24)
        | ((x & 0x00ff000000000000ull) >> 40)
        | ((x & 0xff00000000000000ull) >> 56);
#else
    return x;
#endif
}
/// \brief 8 byte network to host byte order.
#define scion_ntohll(x) scion_htonll(x)

/// \brief Error codes returned by the API.
typedef enum scion_error_t
{
    // success
    SCION_OK = 0, ///< no error
    // generic unknown error
    SCION_ERROR = -1, ///< operation failed
    // alternate success
    SCION_CANCELLED = 1,      ///< operation cancelled
    SCION_PENDING,            ///< operation not completed yet
    SCION_TIMEOUT,            ///< operation timed out
    SCION_SCMP_RECEIVED,      ///< received an SCMP packet
    SCION_STUN_RECEIVED,      ///< received a STUN packet
    SCION_NO_METADATA = 64,   ///< no path metadata available
    SCION_PATH_IS_EMPTY = 65, ///< path is empty
    // errors
    SCION_LOGIC_ERROR = 128,  ///< expected precondition failed
    SCION_NOT_IMPLEMENTED,    ///< not implemented (yet)
    SCION_INVALID_ARGUMENT,   ///< invalid argument
    SCION_SYNTAX_ERROR,       ///< input contains syntax error(s)
    SCION_INVALID_SOCKET,     ///< socket closed or invalid
    SCION_BUFFER_TOO_SMALL,   ///< provided buffer too small to hold output
    SCION_PACKET_TOO_BIG,     ///< packet or payload too big
    SCION_REQUIRES_ZONE,      ///< IPv6 address requires zone identifier
    SCION_NO_LOCAL_HOST_ADDR, ///< no suitable underlay host address found
    SCION_NAME_NOT_FOUND,     ///< name was not found
    SCION_REMOTE_ERROR,       ///< remote machine returned an error
    // packet validation errors
    SCION_INVALID_PACKET = 256, ///< received an invalid packet
    SCION_CHECKSUM_ERROR,       ///< packet checksum incorrect
    SCION_DST_ADDR_MISMATCH,    ///< packet rejected because of unexpected destination address
    SCION_SRC_ADDR_MISMATCH,    ///< packet rejected because of unexpected source address
    // I/O error conditions from I/O subsystems
    SCION_WOULD_BLOCK = 1024, ///< nonblocking operation would block (EAGAIN, EWOULDBLOCK)
    // gRPC control plane communication errors
    SCION_CONTROL_PLANE_RPC_ERROR = 2048, ///< error in communication with control plane services
} scion_error;

/// \brief Get a short description of an error code.
DLLEXPORT
const char* scion_error_string(scion_error err);

/// \brief Type of the AS-internal host address part of a SCION address.
typedef enum scion_host_addr_type_t
{
    SCION_IPv4 = 0x0,
    SCION_IPv6 = 0x3,
} scion_host_addr_type;

/// \brief SCION path types. This library only supports SCION_PATH_SCION.
typedef enum scion_ptype_t
{
    SCION_PATH_EMPTY   = 0,
    SCION_PATH_SCION   = 1,
    SCION_PATH_ONEHOP  = 2,
    SCION_PATH_EPIC    = 3,
    SCION_PATH_COLIBRI = 4,
} scion_ptype;

/// \brief Opaque host context handle.
struct scion_context_t;
typedef struct scion_context_t scion_context;

/// \brief Opaque SCION path as retrieved from the control plane.
struct scion_path_t;
typedef struct scion_path_t scion_path;

/// \brief Opaque SCION path as recovered from the data plane.
struct scion_raw_path_t;
typedef struct scion_raw_path_t scion_raw_path;

/// \brief Opaque handle of a header cache.
struct scion_hdr_cache_t;
typedef struct scion_hdr_cache_t scion_hdr_cache;

/// \brief Opaque socket handle.
struct scion_socket_t;
typedef struct scion_socket_t scion_socket;

/// \brief Opaque handle of an ASIO timer.
struct scion_timer_t;
typedef struct scion_timer_t scion_timer;

///////////
// Clock //
///////////

/// \name Clock
///@{

/// \brief Returns the current UTC time in nanoseconds since the UNIX epoch.
/// This clock follows time adjustments of the host clock, if a steady clock is
/// needed use `scion_time_steady()`.
DLLEXPORT
uint64_t scion_time_utc(void);

/// \brief Retruns the number of nanoseconds elapsed since sum undefined epoch.
/// This clock is monotonically increasing.
DLLEXPORT
uint64_t scion_time_steady(void);

///@}

///////////////
// Addresses //
///////////////

/// \name Addresses
///@{

/// \brief SCION host address. All fields are in network byte order.
struct scion_addr {
    scion_host_addr_type sscion_host_type; ///< Host address type
    uint32_t sscion_scope_id;              ///< IPv6 scope-id
    uint64_t sscion_isd_asn;               ///< SCION ISD and ASN
    /// \brief Host address 4-16 bytes
    union {
        uint8_t sscion_addr[16];
        uint16_t sscion_addr16[8];
        uint32_t sscion_addr32[4];
    } u;
};

/// \brief Initializer for SCION-IPv4 wildcard address.
#define SCIONADDR_ANY4_INIT() { SCION_IPv4, 0, 0, {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} }
/// \brief Initializer for SCION-IPv6 wildcard address.
#define SCIONADDR_ANY6_INIT() { SCION_IPv6, 0, 0, {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} }
/// \brief Test whether the address is unspecified.
#define SCION_IS_ADDR_UNSPECIFIED(a) ( \
    ((const struct scion_addr*)(a))->u.sscion_addr32[0] == 0 \
    && ((const struct scion_addr*)(a))->u.sscion_addr32[1] == 0 \
    && ((const struct scion_addr*)(a))->u.sscion_addr32[2] == 0 \
    && ((const struct scion_addr*)(a))->u.sscion_addr32[3] == 0 \
)
/// \brief Make ISD-ASN from ISD (16 bits) and ASN (48 bits) (in host byte order)
#define SCION_ISD_ASN(isd, asn) (scion_htonll(((uint64_t)isd << 48) | (uint64_t)asn))
/// \brief Extract ISD from ISD-ASN (in host byte order)
#define SCION_ISD_ASN_GET_ISD(isd_asn) ((scion_ntohll(isd_asn) >> 48) & 0xffff)
/// \brief Extract ASN from ISD-ASN (in host byte order)
#define SCION_ISD_ASN_GET_ASN(isd_asn) (scion_ntohll(isd_asn) & 0xffff'ffff'ffff)

/// \brief SCION socket address (endpoint address).
/// All fields except `sscion_family` are in network byte order.
struct sockaddr_scion
{
#if _WIN32
    ADDRESS_FAMILY sscion_family;  ///< AF_SCION
    USHORT sscion_port;            ///< Transport layer port
#else
    sa_family_t sscion_family;     ///< AF_SCION
    in_port_t sscion_port;         ///< Transport layer port
#endif
    uint32_t sscion_flowinfo;      ///< SCION flow information
    struct scion_addr sscion_addr; ///< SCION address
};

///@}

/// \brief A 128-bit hash value.
struct scion_digest
{
    uint64_t value[2];
};

/// \brief Compares two digests for equality.
#define SCION_DIGEST_EQUAL(a, b) (a.value[0] == b.value[0] && a.value[1] == b.value[1])

//////////
// SCMP //
//////////

/// \brief SCMP message types.
typedef enum scion_scmp_type_t
{
    SCION_SCMP_UNKNOWN        = 0,
    SCION_SCMP_DST_UNREACH    = 1,
    SCION_SCMP_PACKET_TOO_BIG = 2,
    SCION_SCMP_PARAM_PROBLEM  = 4,
    SCION_SCMP_EXT_IF_DOWN    = 5,
    SCION_SCMP_INT_CONN_DOWN  = 6,
    SCION_SCMP_ECHO_REQUEST   = 128,
    SCION_SCMP_ECHO_REPLY     = 129,
    SCION_SCMP_TRACE_REQUEST  = 130,
    SCION_SCMP_TRACE_REPLY    = 131,
} scion_scmp_type;

/// \brief SCMP message whose type was not recognized.
struct scion_scmp_unknown
{
    uint8_t code;
};

/// \brief SCMP destination unreachable.
struct scion_scmp_dst_unreach
{
    uint8_t code;
};

/// \brief SCMP packet too big.
struct scion_scmp_packet_too_big
{
    uint8_t code;
    uint16_t mtu;
};

/// \brief SCMP parameter problem.
struct scion_scmp_param_problem
{
    uint8_t code;
    uint16_t pointer;
};

/// \brief SCMP external interface down
struct scion_scmp_ext_if_down
{
    uint8_t code;
    uint64_t sender;
    uint64_t iface;
};

/// \brief SCMP internal connectivity down
struct scion_scmp_int_conn_down
{
    uint8_t code;
    uint64_t sender;
    uint64_t ingress;
    uint64_t egress;
};

/// \brief SCMP echo request/reply.
struct scion_scmp_echo
{
    uint8_t code;
    uint16_t id;
    uint16_t seq;
};

/// \brief SCMP traceroute request/reply.
struct scion_scmp_traceroute
{
    uint8_t code;
    uint16_t id;
    uint16_t seq;
};


/// \brief Represents a received SCMP message.
struct scion_scmp_message
{
    scion_scmp_type type; ///< Message type stored in params.
    /// SCMP message header.
    union {
        struct scion_scmp_unknown unknown;
        struct scion_scmp_dst_unreach dst_unreach;
        struct scion_scmp_packet_too_big packet_too_big;
        struct scion_scmp_param_problem param_problem;
        struct scion_scmp_ext_if_down ext_if_down;
        struct scion_scmp_int_conn_down int_conn_down;
        struct scion_scmp_echo echo;
        struct scion_scmp_traceroute traceroute;
    } params;
    struct scion_addr from;     ///< Source address fo the message.
    const scion_raw_path* path; ///< Unprocessed path the message was received from.
    const uint8_t* payload;     ///< Message payload after the header.
    size_t payload_len;         ///< Length of payload.
};

typedef void (*scion_scmp_handler)(const struct scion_scmp_message* message, void* user_ptr);

//////////////////
// Host Context //
//////////////////

/// \name Host Context
///@{

#define SCION_HOST_CTX_MTU_DISCOVER 0x01

struct scion_context_opts
{
    /// \brief Address of local SCION daemon. If NULL, will not connect to
    /// daemon. If not connecting to daemon, `default_isd_asn`, `ports_begin`,
    /// and `ports_end` must be set manually.
    const char* daemon_address;
    /// \brief Override the default local ISD-ASN. Set to zero to determine
    /// automatically.
    uint64_t default_isd_asn;
    /// \brief Together with ports_end forms the closed interval of ports used
    /// by SCION. Set `parts_begin` and `ports_end` to 0 to determine
    /// automatically.
    uint16_t ports_begin;
    /// \brief Together with ports_begin forms the closed interval of ports used
    /// by SCION. Set `parts_begin` and `ports_end` to 0 to determine
    /// automatically.
    uint16_t ports_end;
    /// \brief Flags that modify the behavior if the context and its sockets.
    /// \details Possible values are a combination of the following flags:
    /// - `SCION_HOST_CTX_MTU_DISCOVER` Enable Path MTU discovery via SCMP
    ///   messages. If this option is enabled, the maximum size of a SCION
    ///   datagram can be calculated using scion_path_discoverd_mtu(),
    ///   scion_raw_path_discovered_mtu() and scion_measure(). Even when PMTU
    ///   discovery is enabled, sockets are not guaranteed to return
    ///   SCION_PACKET_TOO_BIG if the resulting packet is too big.
    int flags;
};

/// \brief Create a host context with the options given by a scion_context_opts
/// struct. pctx and opts must not be NULL. The options struct is no longer
/// required after the function returns and can be safely deallocated.
DLLEXPORT
scion_error scion_create_host_context(scion_context** pctx, const struct scion_context_opts* opts);

/// \brief Delete a host context. Deleting NULL has no effect.
DLLEXPORT
void scion_delete_host_context(scion_context* ctx);

/// \brief Set a global callback for SCMP messages received on any socket.
/// Set to callback to NULL to disable it again.
/// \returns The previously stored value of user_ptr.
DLLEXPORT
void* scion_set_scmp_handler(
    scion_context* ctx, scion_scmp_handler handler, void* user_ptr);

/// \brief Returns the dynamically discovered PMTU between the local host and
/// `dest` via `path`. If PMTU discovery is disabled this value matches
/// `scion_path_mtu(path)`.
/// \returns 0 if no PMTU is known or the arguments are invalid. Otherwise, the
/// PMTU in bytes.
DLLEXPORT
uint16_t scion_discovered_pmtu(scion_context* ctx, scion_path* path, const struct scion_addr* dest);

/// \brief Returns the dynamically discovered PMTU between the local host and
/// `dest` via `path`.
/// \returns 0 if no PMTU is known or the arguments are invalid. Otherwise, the
/// PMTU in bytes.
DLLEXPORT
uint16_t scion_discovered_pmtu_raw(
    scion_context* ctx, scion_raw_path* path, const struct scion_addr* dest);

/// \brief Execute callbacks for operations that have completed.
/// \returns The number of callbacks that have been executed.
DLLEXPORT
size_t scion_poll(scion_context* ctx);

/// \brief Run the ASIO event loop until no more work remains.
/// \returns The number of callbacks that have been executed.
DLLEXPORT
size_t scion_run(scion_context* ctx);

/// \brief Run the ASIO event loop until no more work remains or the timeout
/// elapses.
/// \param timeout Timeout in milliseconds.
/// \returns The number of callbacks that have been executed.
DLLEXPORT
size_t scion_run_for(scion_context* ctx, uint32_t timeout);

/// \brief Signal all running event loops to stop and returns as soon as
/// possible.
DLLEXPORT
void scion_stop(scion_context* ctx);

/// \brief Must be called after all invocations of scion_poll(), scion_run(),
/// scion_run_for() have returned before any of these functions is called again.
/// Must not be called while scion_poll(), scion_run(), or scion_run_for() are
/// still running. See boost::asio::io_context::restart for more information.
DLLEXPORT
void scion_restart(scion_context* ctx);

///@}

///////////////
// Addresses //
///////////////

/// \name Addresses
///@{

/// \brief Test whether two addresses are equal.
DLLEXPORT
bool scion_addr_are_equal(const struct scion_addr* a, const struct scion_addr* b);

/// \brief Test whether two sockaddr_scion are equal.
DLLEXPORT
bool scion_sockaddr_are_equal(const struct sockaddr_scion* a, const struct sockaddr_scion* b);

/// \brief Returns the AS-internal host address from `saddr` in the buffer
/// pointed to by `host`. `host_len` is the size of the buffer pointed to by
/// `host` in bytes.
/// \returns If the buffer is too small to hold the host socket address,
/// SCION_BUFFER_TOO_SMALL is returned. If `saddr` is invalid,
/// SCION_INVALID_ARGUMENT is returned.
DLLEXPORT
scion_error scion_sockaddr_get_host(
    const struct sockaddr_scion* saddr, struct sockaddr* host, socklen_t host_len);

/// \brief Splits an IP or SCION address into host address and optional port.
/// \param[in] addr null-terminated input string.
/// \param[out] host Receives a pointer into `addr` at the first byte of the
/// host address part.
/// \param[out] host_len Receives the length of the host address.
/// \param[out] port Receives the numerical port or zero if the address did not
/// contain a port.
DLLEXPORT
scion_error scion_split_host_port(
    const char* addr, const char** host, size_t* host_len, uint16_t* port);

/// \brief Parses a SCION host address without a port.
DLLEXPORT
scion_error scion_parse_host(const char* host, struct scion_addr* addr);

/// \brief Parses a SCION address with a port.
DLLEXPORT
scion_error scion_parse_ep(const char* endpoint, struct sockaddr_scion* sockaddr);

/// \brief Formats a SCION address as a null-terminated string to the buffer
/// pointed to by `buffer`. `buffer_len` should be initialized to the size of
/// the puffer pointed to by `buffer`. On return it contains the actual size of
/// the output (including the null terminator).
///
/// The returned string is truncated if the provided buffer is too small. In
/// this case, `buffer_len` will contain a value greater than was supplied and
/// SCION_BUFFER_TOO_SMALL is returned. As long as the buffer has a non-zero
/// size, the returned string is guaranteed to be null-terminated.
DLLEXPORT
scion_error scion_print_host(const struct scion_addr* addr, char* buffer, size_t* buffer_len);

/// \brief Formats a SCION socket address as a null-terminated string to the
/// buffer pointed to by `buffer`. `buffer_len` should be initialized to the
/// size of the puffer pointed to by `buffer`. On return it contains the actual
/// size of the output (including the null terminator).
///
/// The returned string is truncated if the provided buffer is too small. In
/// this case, `buffer_len` will contain a value greater than was supplied and
/// SCION_BUFFER_TOO_SMALL is returned. As long as the buffer has a non-zero
/// size, the returned string is guaranteed to be null-terminated.
DLLEXPORT
scion_error scion_print_ep(const struct sockaddr_scion* addr, char* buffer, size_t* buffer_len);

///@}

/////////////////////
// Name Resolution //
/////////////////////

/// \brief Resolve a numerical or symbolic host address to SCION socket
/// addresses in the buffer pointed to by `res`. `res_len` should be initialized
/// to the length of the buffer in the number of sockaddr_scion structures and
/// will contain the number of available addresses upon return.
///
/// If the provided buffer is too small to hold all available addresses, the
/// result is truncated, `res_len` will contain a value greater than the one
/// originally supplied, and the function returns SCION_BUFFER_TOO_SMALL.
///
/// The address resolution proceeds according to the steps outlined in
/// scion::Resolver.
DLLEXPORT
scion_error scion_resolve_name(scion_context* ctx,
    const char* name, struct sockaddr_scion* res, size_t* res_len);

struct scion_async_resolve_handler
{
    void (*callback)(scion_error err, void* user_ptr);
    void* user_ptr;
};

/// \brief Same as scion_resolve_name, but returns immediately without waiting
/// for the name resolution to complete. Once the result is ready `handler`
/// is invoked with the given context pointer. The output buffers `res` and
/// `res_len` must remain valid during the entire duration of the asynchronous
/// operation.
DLLEXPORT
void scion_resolve_name_async(scion_context* ctx,
    const char* name, struct sockaddr_scion* res, size_t* res_len,
    struct scion_async_resolve_handler handler);

///////////
// Paths //
///////////

/// \name Path
///@{

/// \brief SCION AS-hop information.
struct scion_hop
{
    uint64_t isd_asn; ///< ISD-ASN of this hop.
    uint64_t ingress; ///< AS ingress interface in path direction.
    uint64_t egress;  ///< AS egress interface in path direction.
};

/// \brief Queries paths to the AS identified by ISD-ASN `dst` (in host byte
/// order) from the control plane. Paths are cached by the library, so calls may
/// complete immediately.
///
/// `paths` should point to a buffer that can hold up to `paths_len` scion_path
/// handles. On return `paths_len` will contain the actual number of available
/// paths which may be larger than the value passed originally. If the provided
/// buffer is too small, the result is truncated and SCION_BUFFER_TOO_SMALL is
/// returned.
DLLEXPORT
scion_error scion_query_paths(
    scion_context* ctx, uint64_t dst, scion_path** paths, size_t* paths_len);

/// \brief Releases paths in the array pointed to by `paths`. `path_len` is the
/// number of paths in the array. Array entries that are NULL are ignored.
/// after the function returns all entries in `paths` are NULL.
DLLEXPORT
void scion_release_paths(scion_path** paths, size_t paths_len);

/// \brief Gets the first AS along the path (the source).
/// \returns ISD-ASN in host byte order.
DLLEXPORT
uint64_t scion_path_first_as(scion_path* path);

/// \brief Gets the last AS along the path (the destination).
/// \returns ISD-ASN in host byte order.
DLLEXPORT
uint64_t scion_path_last_as(scion_path* path);

/// \brief Gets the path type.
DLLEXPORT
scion_ptype scion_path_type(scion_path* path);

/// \brief Returns the expiration time of the path in nanoseconds since the
/// Unix epoch. The time is given in UTC.
DLLEXPORT
uint64_t scion_path_expiry(scion_path* path);

/// \brief Returns the path's MTU as reported by the control plane.
DLLEXPORT
uint16_t scion_path_mtu(scion_path* path);

/// \brief Reports the status of the path's broken flag. A value of zero means
/// that the path is considered working. A non-zero return value indicates the
/// last time the path was flagged as broken, for example by an interface down
/// or internal connectivity down SCMP message. Non-zero timestamps can be
/// compared to the current time as returned by `scion_time_steady()` to
/// determine how long ago the path was last tried.
DLLEXPORT
uint64_t scion_path_broken(scion_path* path);

/// \brief Change the value of the path's broken flag. A value of zero indicates
/// the path is working. A non-zero value should be the timestamp as returned by
/// `scion_time_steady()` when the path was discovered to be broken.
DLLEXPORT
void scion_path_set_broken(scion_path* path, uint64_t broken);

/// \brief Returns ISD-ASN and interface metadata for each hop on the path.
/// If the path does not contain metadata, SCION_NO_METADATA is returned and
/// nothing is written.
///
/// The `hops_len` argument should be initialized to the length of the buffer
/// pointed to by `hops`. On return it contains the actual number of hops
/// written. If the buffer did not provide adequate space, the result is
/// truncated, `hops_len` is set to the full length of the result and
/// SCION_BUFFER_TOO_SMALL is returned.
DLLEXPORT
scion_error scion_path_meta_hops(
    scion_path* path, struct scion_hop* hops, size_t* hops_len);

/// \brief Returns the length of the path in inter-AS hops (i.e., the number of
/// visited ASes - 1). This value is derived from the raw data plane path and
/// does not necessarily match the hop count given by metadata.
DLLEXPORT
uint32_t scion_path_hop_count(scion_path* path);

/// \brief Returns the path digest in `digest`.
DLLEXPORT
void scion_path_digest(scion_path* path, struct scion_digest* digest);

/// \brief Returns the underlay next hop address in the buffer pointed to by
/// `next_hop`. `next_hop_len` should be initialized to the size of the buffer
/// pointed to by `next_hop` in bytes. On return it contains the actual size of
/// the socket address.
///
/// \returns If the buffer is too small, the address is truncated and
/// SCION_BUFFER_TOO_SMALL is returned. If the path does not have a next hop
/// address because it is empty, SCION_PATH_IS_EMPTY is returned.
DLLEXPORT
scion_error scion_path_next_hop(
    scion_path* path, struct sockaddr* next_hop, socklen_t* next_hop_len);

/// \brief Returns a pointer to an internal buffer holding the encoded data
/// plane representation of the path in `encoded`. `encoded_len` is set to the
/// size of the data plane path in bytes.
DLLEXPORT
void scion_path_encoded(scion_path* path, const uint8_t** encoded, size_t* encoded_len);

/// \brief Formats a SCION path as a null-terminated string to the buffer
/// pointed to by `buffer`. `buffer_len` should be initialized to the size of
/// the puffer pointed to by `buffer`. On return it contains the actual size of
/// the output (including the null terminator).
///
/// The returned string is truncated if the provided buffer is too small. In
/// this case, `buffer_len` will contain a value greater than was supplied and
/// SCION_BUFFER_TOO_SMALL is returned. As long as the buffer has a non-zero
/// size, the returned string is guaranteed to be null-terminated.
DLLEXPORT
scion_error scion_path_print(scion_path* path, char* buffer, size_t* buffer_len);

///@}

///////////////
// Raw Paths //
///////////////

/// \name Raw Path
///@{

/// \brief Allocates storage for a raw path.
DLLEXPORT
scion_raw_path* scion_raw_path_allocate(void);

/// \brief Frees memory allocated by scion_raw_path(). Freeing a NULL pointer
/// has no effect.
DLLEXPORT
void scion_raw_path_free(scion_raw_path* path);

/// \copydoc scion_path_encoded()
DLLEXPORT
void scion_raw_path_encoded(scion_raw_path* path, const uint8_t** encoded, size_t* encoded_len);

/// \copydoc scion_path_first_as()
DLLEXPORT
uint64_t scion_raw_path_first_as(scion_raw_path* path);

/// \copydoc scion_path_last_as()
DLLEXPORT
uint64_t scion_raw_path_last_as(scion_raw_path* path);

/// \copydoc scion_path_type()
DLLEXPORT
scion_ptype scion_raw_path_type(scion_raw_path* path);

/// \copydoc scion_path_digest()
DLLEXPORT
void scion_raw_path_digest(scion_raw_path* path, struct scion_digest* digest);

/// \brief Turn this path into its reverse without fully decoding it. Supported
/// path types are Empty and SCION paths.
DLLEXPORT
scion_error scion_raw_path_reverse(scion_raw_path* path);

/// \copydoc scion_path_print()
DLLEXPORT
scion_error scion_raw_path_print(scion_raw_path* path, char* buffer, size_t* buffer_len);

///@}

//////////////////
// Header Cache //
//////////////////

/// \name Header Cache
///@{

/// \brief Allocates storage for assembling SCION headers.
DLLEXPORT
scion_hdr_cache* scion_hdr_cache_allocate(void);

/// \brief Frees memory allocted by scion_hdr_cache_allocate(). Freeing a NULL
/// pointer has no effect.
DLLEXPORT
void scion_hdr_cache_free(scion_hdr_cache* headers);

///@}

/////////////
// Sockets //
/////////////

/// \name Socket
///@{

/// \brief Creates a SCION socket and returns it's handler in `socket`.
/// 'socket_type` is a socket type such as SOCK_STREAM or SOCK_DGRAM. Currently
/// only SOCK_DGRAM is supported.
///
/// After a socket has been created it is not open yet. Before calling any of
/// the send or receive functions, the socket must be opened by calling
/// scion_bind().
DLLEXPORT
scion_error scion_socket_create(scion_context* ctx, scion_socket** socket, int socket_type);

/// \brief Closes a socket and releases all associated memory. Closeing a NULL
/// handle has no effect.
DLLEXPORT
void scion_close(scion_socket* socket);

/// \brief Binds a socket to the socket address pointed to by `addr`. `addr_len`
/// should be set to the length of the buffer pointed to by `addr`.
DLLEXPORT
scion_error scion_bind(scion_socket* socket, const struct sockaddr* addr, socklen_t addr_len);

/// \brief Connects to a remote endpoint.
///
/// In case of a connectionless socket, store the default address for send
/// operations. After the socket is connected no other packets than those from
/// the connected address are received. Call with an unspecified address to
/// again receive from all remote addresses.
DLLEXPORT
scion_error scion_connect(scion_socket* socket, const struct sockaddr_scion* addr);

/// \brief Returns whether the socket is open, i.e., scion_bind() has returned
/// successfully.
DLLEXPORT
bool scion_is_open(scion_socket* socket);

#if _WIN32
typedef SOCKET scion_native_handle;
#else
typedef int scion_native_handle;
#endif

/// \brief Returns the native handle of the underlying UDP socket.
///
/// The native handle can be used to with an I/O multiplexing function such as
/// `poll()` or `epoll()`.
DLLEXPORT
scion_native_handle scion_underlay_handle(scion_socket* socket);

/// \brief Switch the underlying socket between blocking and non-blocking I/O
/// modes. On some OSes it might not be possible to return a nonblocking socket
/// to blocking mode. Using any of the asynchronous function on the socket can
/// switch the socket into non-blocking mode automatically, so manually
/// switching to non-blocking is only useful when using the synchronous API.
DLLEXPORT
scion_error scion_set_nonblocking(scion_socket* socket, bool nonblocking);

/// \brief Returns the current address to which the socket is bound in `addr`.
DLLEXPORT
void scion_getsockname(scion_socket* socket, struct sockaddr_scion* addr);

/// \brief Returns the local address after SNAT. Differs from
/// scion_getsockname() if and only if NAT traversal is active.
DLLEXPORT
void scion_getmapped(scion_socket* socket, struct sockaddr_scion* addr);

/// \brief Returns the currently connected remote address in `addr`.
DLLEXPORT
void scion_getpeername(scion_socket* socket, struct sockaddr_scion* addr);

/// \brief SCION packet parameters.
struct scion_packet
{
    struct sockaddr_scion* addr; ///< SCION source/destination address.
    struct sockaddr* underlay;   ///< Underlay source/destination address.
    socklen_t underlay_len;      ///< Size of the address pointed to by `underlay`in bytes.
    int _path_type;              ///< Path type. Set via SCION_SET_PATH() macro.
    void* _path;                 ///< Pointer to data plane path. Set via SCION_SET_PATH() macro.
};

#ifdef __cplusplus
/// \brief Associates a path with a scion_packet struct. Set the path to NULL
/// to reset the association.
#define SCION_SET_PATH(packet, path) do { \
    if constexpr (std::is_same_v<std::decay_t<decltype(path)>, scion_path*>) { \
        packet._path_type = 1; \
    } else if constexpr (std::is_same_v<std::decay_t<decltype(path)>, scion_raw_path*>) { \
        packet._path_type = 2; \
    } else { \
        assert(path == NULL); \
    } \
    packet._path = (path); \
} while(0)
#else
/// \brief Associates a path with a scion_packet struct. Set the path to NULL
/// to reset the association.
#define SCION_SET_PATH(packet, path) { \
    packet._path_type = _Generic((path), default: 0, scion_path*: 1, scion_raw_path*: 2); \
    packet._path = (path); \
}
#endif

/// \brief Calculate the total size of the SCION and L4 headers on the wire if a
/// packet would be sent with the given parameters.
///
/// \param[in] args Packet arguments. This function calculates the header size
/// from the destination address `args->addr` (optional for connected sockets)
/// and the path which should be initialized by calling SCION_SET_PATH with a
/// scion_path or scion_raw_path. The underlay address is ignored.
/// \param[out] hdr_size Pointer to a size_t that is set to the calculated
/// header size on successful return.
/// \returns Returns an error if argument validation fails. Does not return I/O
/// errors as this function does not perform socket I/O.
DLLEXPORT
scion_error scion_measure(
    scion_socket* socket, const struct scion_packet* args, size_t* hdr_size);

/// \brief Send a STUN binding request to the given router and prepare the
/// the scion_recv* functions to expect a STUN response.
DLLEXPORT
scion_error scion_request_stun_mapping(scion_socket* socket, struct sockaddr* router,
    socklen_t router_len);

/// \brief Transmits a message.
///
/// \param[in] headers Pointer to a header cache. Must not be NULL. If the same
/// cache is used with the same packet arguments (destination address, path,
/// etc.) you can pass it to scion_send_cached() to reuse the same headers and
/// save some processing time.
/// \param[in] buf Pointer to a buffer holding the data to be sent.
/// \param[inout] n Should be initialized to the size of the buffer pointed to
/// by `buf`. On return contains the number of bytes actually sent.
/// \param[in] args Packet arguments. `args->addr` is the destination of the
/// message. `args->underlay` is the underlay next hop address and
/// `args->underlay_len` it's size in bytes. The path should be initialized by
/// calling SCION_SET_PATH with a scion_path or scion_raw_path.
///
/// If the socket is connected, the destination address can be omitted (set
/// `args->addr` to NULL). If no destination is supplied, but the socket is not
/// connected, the error SCION_INVALID_ARGUMENT is returned. Path and underlay
/// address are mandatory arguments and must not be NULL.
DLLEXPORT
scion_error scion_send(
    scion_socket* socket, scion_hdr_cache* headers, const void* buf, size_t* n,
    const struct scion_packet* args);

/// \brief Transmits a message, reusing the SCION headers created by a previous
/// call to scion_send() or scion_send_async(). It is the programmers
/// responsibility to ensure that the headers passed in are valid and actually
/// match the desired destination and path.
DLLEXPORT
scion_error scion_send_cached(
    scion_socket* socket, scion_hdr_cache* headers, const void* buf, size_t* n,
    struct scion_packet* args);

/// \brief Receive packets until a STUN response matching the last request
/// made with scion_request_stun_mapping() or scion_request_stun_mapping_async()
/// is found.
DLLEXPORT
scion_error scion_recv_stun_response(scion_socket* socket);

/// \brief Receive messages from a socket.
///
/// \param[out] buf Pointer to a buffer in which the messages are received.
/// \param[inout] n Should be initialized to the size of the buffer pointed to
/// by `buf`. On return contains the number of bytes actually received.
/// \param[inout] args The structure pointed to be `args` should be prepared by
/// setting `args->addr` to point to a SCION socket address that will contain
/// the source of the messages. `args->addr` may be NULL of the source address
/// should not be returned. `args->underlay` should point to a buffer that
/// receives the underlay source address that can hold at least
/// `args->underlay_len` bytes. If the buffer size is insufficient, the receive
/// operation fails with SCION_INVALID_ARGUMENT. Therefore, it is recommended to
/// set `args->underlay` to a `sockaddr_storage` buffer which is guaranteed to
/// be sufficiently sized. Alternatively, `args->underlay` may be NULL, if the
/// underlay address should not be returned. If the path the messages were
/// received on is to be returned, a scion_raw_path must have been associated
/// with the scion_packet struct. If the path is NULL, no path information is
/// returned.
DLLEXPORT
void* scion_recv(
    scion_socket* socket, void* buf, size_t* n, struct scion_packet* args, scion_error* err);

struct scion_async_send_handler
{
    /// \param err Return code of the operation that completed.
    /// \param n Number of bytes that have been sent.
    /// \param user_ptr Pointer provided in scion_async_send_handler.
    void (*callback)(scion_error err, size_t n, void* user_ptr);
    void* user_ptr;
};

/// \brief Same as scion_request_stun_mapping(), but returns immediately without
/// waiting for the send operation to complete. On completion, `handler` is
/// called with any potential error code.
DLLEXPORT
void scion_request_stun_mapping_async(scion_socket* socket, struct sockaddr* router,
    socklen_t router_len, struct scion_async_send_handler handler);

/// \brief Same as scion_send(), but returns immediately without waiting for the
/// send operation to complete. On completion, `handler` is called with any
/// potential error code and the number of bytes sent.
///
/// The buffers supplied when initiating the asynchronous operation must remain
/// valid until the completion handler is called.
DLLEXPORT
void scion_send_async(
    scion_socket* socket, scion_hdr_cache* headers, const void* buf, size_t n,
    const struct scion_packet* args, struct scion_async_send_handler handler);

/// \brief Same as scion_send_cached(), but returns immediately without waiting
/// for the send operation to complete. On completion, `handler` is called with
/// any potential error code and the number of bytes sent.
///
/// The buffers supplied when initiating the asynchronous operation must remain
/// valid until the completion handler is called.
DLLEXPORT
void scion_send_cached_async(
    scion_socket* socket, scion_hdr_cache* headers, const void* buf, size_t n,
    struct scion_packet* args, struct scion_async_send_handler handler);

struct scion_async_recv_handler
{
    /// \param err Return code of the operation that completed.
    /// \param n Number of bytes that have been received.
    /// \param user_ptr Pointer provided in scion_async_recv_handler.
    void (*callback)(scion_error err, void* recvd, size_t n, void* user_ptr);
    void* user_ptr;
};

/// \brief Same as scion_recv_stun_response(), but returns immediately without
/// waiting for messages to be received. When the asynchronous operation
/// completes, `handler` is called with any potential error code.
DLLEXPORT
void scion_recv_stun_response_async(scion_socket* socket,
    struct scion_async_recv_handler handler);

/// \brief Same as scion_recv(), but returns immediately without waiting for
/// messages to be received. When the asynchronous operation completes,
/// `handler` is called with any potential error code and the number of bytes
/// received.
///
/// The buffers supplied when initiating the asynchronous operation must remain
/// valid until the completion handler is called.
DLLEXPORT
void scion_recv_async(scion_socket* socket, void* buf, size_t n, struct scion_packet* args,
    struct scion_async_recv_handler handler);

/// \brief Cancel all asynchronous operations associated with the socket. Calls
/// `cancel()` on the underlying ASIO socket.
DLLEXPORT
scion_error scion_cancel(scion_socket* socket);

///@}

////////////
// Timers //
////////////

/// \name Timer
///@{

/// \brief Allocates a timer. Before the timer can be waited on it's timeout
/// must be set with scion_timer_set_timeout().
DLLEXPORT
scion_timer* scion_timer_allocate(scion_context* ctx);

/// \brief Frees a timer allocated by scion_timer_allocate(). Freeing a NULL
// handle has no effect.
DLLEXPORT
void scion_timer_free(scion_timer* timer);

/// \brief Sets the timers expiration time relative to now. After the timer has
/// expired or was cancelled a new timeout should be set by calling this
/// function again.
/// \param timeout Timeout in milliseconds.
DLLEXPORT
void scion_timer_set_timeout(scion_timer* timer, uint32_t timeout);

/// \brief Cancels all asynchronous operations waiting on the timer. The
/// handlers of cancelled operations are invoked with SCION_CANCELLED. However,
/// if the invocation of a handler was already scheduled when the operation is
/// cancelled, it is still going to execute with it's normal error code. See
/// `boost::asio::basic_waitable_timer::cancel()`for more information.
/// \returns The number of operations that were cancelled.
DLLEXPORT
size_t scion_timer_cancel(scion_timer* timer);

/// \brief Blocks until the timer expires.
DLLEXPORT
scion_error scion_timer_wait(scion_timer* timer);

struct scion_wait_handler
{
    void (*callback)(scion_error err, void* user_ptr);
    void* user_ptr;
};

/// \brief Initiate an asynchronous wait against the timer and returns
/// immediately. `handler` is invoked when the timer expires or is cancelled.
DLLEXPORT
void scion_timer_wait_async(scion_timer* timer, struct scion_wait_handler handler);

///@}

#ifdef __cplusplus
} // extern "C"
#endif
