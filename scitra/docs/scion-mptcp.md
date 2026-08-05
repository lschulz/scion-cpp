Scitra MPTCP over SCION Protocol amd Implementation Details
===========================================================

Scitra can translate MPTCP subflows to and from SCION. Scitra is compatible with MPTCP v1 as
described in [RFC 8684](https://datatracker.ietf.org/doc/html/rfc8684). As Scitra needs to parse
MPTCP options and interact with MPTCP's cryptography, future versions of MPTCP may not work without
changes to Scitra. Scitra should work with all standard implementations of MPTCP v1 including MPTCP
proxies, but has only been tested with the Linux kernel implementation.

MPTCP allows TCP sockets to use multiple pairs of distinct source and destination addresses to form
subflows over which the TCP stream is load balanced. MPTCP on the wire is implemented as a set of
TCP extension headers. MPTCP subflows are identified by 4-tuple, i.e., the source and destination IP
and port. During a subflow SYN exchange, the entire connection is also identified by a token. Tokens
are cryptographically created from keys exchanged during the initial TCP handshake and are used as
Connection IDs by the end points. As Scitra does not have access to the internal state of the MPTCP
implementation, it learns the keys and tokens passively observing subflow handshakes. Translation
also works if Scitra does not observe all subflow handshakes, for example because some subflows are
not routed through SCION.

To expose SCION paths to MPTCP, Scitra-TUN assigns additional IPv6 addresses to the TUN interface it
creates. We call these IPs surrogate addresses. Surrogate addresses (and the usual IPv6 assigned to
the TUN interface) are used as source addresses by MPTCP. For each source address there can be a
separate subflow with the same ports and destination address. In SCION-IP Translation, the
destination address is usually fixed to the SCION-mapped IPv6 of the destination host. Therefore,
there can be up to the number of surrogate addresses plus one subflows per MPTCP/SCION connection,
plus any number of subflows that do not pass through Scitra and SCION.

Scitra identifies subflows on the host (TUN interface) side by source address, and on the SCION side
by SCION path. Scitra guarantees that all MPTCP/SCION subflows belonging to the same connection
share the same source and destination port, and destination address. Only the source IP varies.
Scitra can rewrite the local (source) port of packets in order to enforce this invariant even if the
underlying MPTCP implementation does not keep the same port, as reusing the same port is only a
SHOULD in RFC 8684 (Section 3.9.1). If future native MPTCP/SCION implementations do not use the same
port for all subflows, Scitra will still work, but may map multiple subflows to the same path. Once
a subflow has been translated to SCION it is distinguished from other subflows only be SCION path.
Therefore, the SCION path of a subflows must remain constant during the entire lifetime of the
subflow, and servers MUST map the return packets to the same SCION path the subflow's SYN was
received on. If either client or server want to change paths, they must do so by establishing a new
subflow on the desired path. After the new flow is open, they may tear down the subflow on the
previous path.

Subflow Management and Path Selection
-------------------------------------

MPTCP uses a *path manager* to control when and how often subflows are created or torn down. Scitra
can currently not influence subflow creation directly and relies on the in-kernel path manager on
Linux which can be configured using the `ip mptcp` command. Scitra selects a SCION path for each
subflows following a simple rule. Available paths are first filtered and sorted by path policy, then
paths are assigned one-by-one using a greedy algorithm that prefers path that have the least
AS-interface (or equivalently inter-AS link) overlap.

There are two situations in which Scitra must intervene in subflow creation. (1) On an outgoing SYN,
if there are more surrogate addresses/subflows than available paths, and (2) on an incoming SYN if
there are more paths than available surrogate addresses. In case (1), Scitra generates a RST packet
that is delivered back to the local MPTCP socket with an MPTCP option giving the reason "lack of
resources" for the RST. Receiving this packet tells the local MPTCP stack that no additional
subflows can be established to this destination. In case (2), a RST is send back to the remote host.
The reset reason is given as "administratively prohibited", as in this case the remote is trying to
establish more subflows than Scitra-TUN was configured for. The effect is the same as in (1), the
remote host will stop trying to establish additional subflows.

A customizable path manager and programmable path selector are under development.
