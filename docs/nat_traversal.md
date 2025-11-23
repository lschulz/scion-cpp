NAT Traversal
=============

Usually SCION hosts require IP address that are routable in their home AS. If there is a NAT router
between the host and the next hop border router, return traffic is not delivered to the correct
address. SCION-CPP includes support for STUN in order to work around NAT-related routing issues.

Background
----------

#### The UDP/IP Underlay ####
SCION traffic is usually transmitted over an UDP/IP underlay. UDP packets exchanged between end
hosts or between a host and a border router contain the SCION header in their payload.
Consequentially, a typical SCION packet contains two sets of IP addresses, one for the underlay and
one as the "host" addresses in the SCION address header. Additionally there are two sets of source
and destination port, one for the UDP underlay and one in the actual transport header following the
SCION path header. The underlay addresses change from AS hop to AS hop, the addresses in the SCION
header stay the same end to end. SCION border routers that deliver a packet to the interior of their
own AS copy the IP address from the SCION header and the destination port from the inner transport
header to the underlay in order to deliver the packet to its final destination.

#### SCION Host behind NAT Problem ####
An unfortunate problem occurs when there is NAT (Source NAT) between the host and the border router.
The NAT will modify the source address (the host's private IP) and replace it with a public IP (the
mapped IP). The underlay UDP port will also be modified to distinguish multiple private IPs sharing
the same public IP. Such a modified packet will still reach the border router and is forwarded
correctly. However, in order to send a reply the recipient of the packet only has the IP address and
port from the SCION and inner transport header, respectively. Since, the NAT does not know about
SCION, the SCION host address and port are still the original private IP and port. When the reply
packet reaches the final border router, this router will incorrectly attempt to deliver to packet to
the private IP instead of the mapped IP.

#### Possible Solution ####
The connection through the NAT is almost working. The only issue is that the NAT did not also
rewrite the SCION source address. Since it would be difficult to replace all NATs with SCION-aware
NAT, we have to do the NAT translation already on the sending host. By writing the mapped IP and
port to the SCION address header and inner transport header, the packet is correct when it reaches
the first border router. In order to find the mapped IP and port on the sending hosts, we can send
a request to the border router to tell us what the source address of the request packet is. The
protocol used for discovering the address mapping is STUN.

#### STUN ####
The Session Traversal Utilities for NAT (STUN) are defined in [RFC 5389][1]. We're only using a
small subset of the protocol, namely binding requests and responses that tell us what public IP
address and port the border router is seeing.

[1]: https://datatracker.ietf.org/doc/html/rfc5389

NAT Traversal in SCION-CPP
--------------------------

POSIX and ASIO sockets support SCION NAT traversal. If the external mapped address and port are
already known (e.g. through an out-of-band mechanism), they can be set using the method
`setMappedIpAndPort()`. Otherwise, a STUN binding request may be sent to a STUN server with the
`requestStunMapping()` method. When a request is sent, the socket will wait for the first STUN
response that corresponds to the request and update the sockets internal address mapping. Additional
STUN responses that may be received are ignored. All receive methods can decode STUN replies that
are multiplexed with normal SCION traffic on the socket's underlay port. `requestStunMapping()` may
be called at any time after the socket has been bound and may be called more than once. After every
call to `requestStunMapping()`, the next valid STUN response updates the mapped address and port.
The current mapped address and port can be retrieved with `mappedEp()`. To disable the NAT traversal
feature, simply set the mapped address equal to the local bind address returned by `localEp()`.

Applications can start sending data before the address mapping is known, or wait for a STUN response
by waiting on `recvStunResponse()`. Other receive methods silently updated the mapped endpoint
address and continue waiting for data to arrive. To return from receive methods when a valid STUN
response is received, set the flag `SMSG_RECV_STUN`.

The helper function `getStunMapping()` automates address discovery with STUN for POSIX-style
sockets. It sends a STUN request and blocks until a response is received. The request is
automatically resent after a timeout until a maximum number of tries is reached.

#### Selecting a STUN Server ####
It is the application's responsibility to discover whether STUN is required, if the AS provides a
STUN server and at what address. If there is STUN server, the recommended address in order of
preference is:
1. The same IP and underlay port as the border router.
2. The same IP ad the border router, but at the default port for STUN (3478).
3. A STUN server in the same IP network as the border router(s) but at a different IP.

If the AS has more than one border router, the mapped address may differ depending on which router
is used. Since SCION-CPP sockets store only a single mapped address for all border routers, it may
be necessary to update the mapped IP and port when switching to a different border router. In
practice such a setup should be rare, however.

Examples
--------

The following examples support STUN and NAT traversal:
- `examples/echo_udp`
- `examples/echo_udp_async`
- `examples/c/echo_udp`
- `examples/c/echo_udp_async`
