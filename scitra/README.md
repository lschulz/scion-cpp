Scitra: The SCION-IP Translator
===============================

SCION-IP Translation is a technique that bridges IPv6 networks via a SCION backbone by directly
translating between the respective header formats. Translators may be deployed on end hosts in which
case they enable applications on the host to communicate with their SCION counterparts, or they can
work as an IPv6 gateway to the SCION network for an entire AS.

The key features of SCION-IP Translators are:
- Lightweight on the Wire: There are no additional encapsulation headers required. There is no
  additional protocol overhead compared to native SCION.
- Lightweight Processing: Translators do not need to buffer packets for fragmentation and
  reassembly to work around MTU differences between IPv6 and SCION, instead they prefer to signal
  the MTU to the IPv6 network stack using standard mechanisms. Adapting to the MTU is then handled
  by the application code or within the TCP/IP stack.
- Transparent Operation: Host employing a translator are indistinguishable from hosts supporting
  SCION natively to the SCION network. This means that the translation can be one-sided: A host
  behind a translator can communicate with a native SCION host without a translator and vice versa.
- Easy deployment: The SCION-IP translator operates entirely in the data plane. There are no
  additional requirements to the control plane. Translators do not need to coordinate with each
  other.

Since the SCION header contains a strict superset of the information in the IPv6 header, translation
is in IP-to-SCION and SCION-to-IP direction is asymmetric. SCION-to-IP translation is
straightforward, IP addresses are extracted from the SCION address headers and the SCION path is
dropped, as by the point the SCION-IP translator is involved they destination AS has already been
reached. In contrast, IP-to-SCION translation has to solve two problems:
1. Determine the SCION destination address from the IPv6 destination address. SCION addresses add
   a 16-bit ISD and a 48-bit ASN to the IP that are not known to the IPv6 network stack. We solve
   this problem by defining an injective mapping from so called SCION-mapped IPv6 addresses to SCION
   addresses.
2. The AS-interface-level forwarding paths must be selected and encoded in the SCION header. Usually
   there is more than one possible choice of path. In order to select paths that are well suited to
   the needs of different applications and usage scenarios, path policies and path selector
   functions are employed.

Mapping of SCION Addresses to IPv6
----------------------------------

**Note: The format of SCION-mapped IPv6 addresses has been updated on 2026-08-10. The old
BGP-derived SCION-mapped IPv6 addresses are identical to the new Format A, but the mapping of
public SCION ASNs has changed in an incompatible way. The reason for this change is that the
SCION Registry has started to allocated entire 16-bit blocks of ASNs for every registrant which
leaves to little space in the old mapping.**

SCION addresses are are represented as **SCION-mapped IPv6 addresses (SM-IP for short**). We define
SM-IPs as IPv6 addresses with the ULA prefix `fc00::/8` [[RFC 4193]]. `fc00::/8` was chosen as it is
recognized by routers as a local prefix and is not routed on the Internet, but has no officially
defined meaning yet. As SM-IPs are not an officially approved concept consider the usage of
`fc00::/8` as experimental. SM-IPs combine the SCION ISD and ASN, as well as what SCION considers
the host address into one IPv6. As the combined ISD, ASN, and a 16 byte host address (usually an
IPv6 address itself) exceed the 128 bit length of an IPv6 address, only a fraction of the SCION
address space is mapped. The fraction that is mapped however, does cover all existing BGP and SCION
ASes and provides ample space for future growth.

There are multiple classes of SM-IPs, that all share the same common structure in Table 1. The ISD
numbers from 0 to 4095 are represented by 12 bits. This covers all ISDs reserved for private use as
well as all currently possible public ISDs. ISDs > 4096 are still reserved by the upstream
specification, and my not be used. The four most significant bits of the following 40 bits define
the format of the rest of the address. Numbering the bits of an IPv6 address from least significant
as 0 to most significant as 127, these bits are bit 107, 106, 105, and 104. Table 2 lists the
interpretation of the flag bits. x is used to indicate don't care bits. If a bit is a don't care it
is not interpreted as part of the flags and instead belongs to the encoded address (ASN).

<figure>
  <table>
    <tr align="center"><td colspan=6>128-bit IPv6 address</td></tr>
    <tr align="center"><td>8 bit</td><td>12 bit</td><td>4 bit</td><td>40 bit</td><td>64 bit</td></tr>
    <tr align="center"><td>0xfc</td><td>ISD</td><td>flags</td><td>ASN and AS-local prefix</td><td>interface ID</td></tr>
  </table>
  <figcaption>Table 1: Common format of SCION-mapped IPv6 addresses.</figcaption>
</figure>

<figure>
  <table>
    <tr><th>Format</th><th>Bit 107 to 104</th><th>Description</th><th>ISD-ASN Prefix Length</th></tr>
    <tr><td>A</td><td>0xxx</td><td>19-bit BGP ASN</td><td>/40</td></tr>
    <tr><td>B</td><td>10xx</td><td>reserved</td><td></td></tr>
    <tr><td>C</td><td>110x</td><td>reserved</td><td></td></tr>
    <tr><td>D</td><td>1110</td><td>32-bit SCION ASN between 2:0:0 and 2:ffff:ffff</td><td>/56</td></tr>
    <tr><td>E</td><td>1111</td><td>reserved</td><td></td></tr>
  </table>
  <figcaption>Table 2: Interpretation of the flag bits.</figcaption>
</figure>

Format A represents BGP-derived ASNs up to 524,287 (2<sup>19</sup>-1). All BGP ASNs may be used as
SCION ASNs. This format results in a total prefix length of /40, which leaves 24 bits for
AS-internal routing.

Format D represents the public SCION ASNs `2:0:0` to `2:ffff:ffff` in 32 bits. The leading 2 is
implicit and not represented directly. Public SCION ASNs are allocated by the [SCION Registry].
SCION ASNs are allocated in blocks of 65'536 ASNs so that the upper 16 bits represent the
registrant, and the lower 16 bits identify ASes in the registrants allocation. This format results
in a total prefix length of /56, leaving 8 bits for AS-internal routing.

Format B, C, and E are reserved for future expansion and should not be used. Note that no encoding
for private (`ffaa:0:0` to `ffaa:00ff:ffff`) and documentation/sample code ASNs (`ff00:0:0` to
`ff00:0:ffff`) is provided. It is recommended to use the equivalent ranges of BGP ASNs instead, see
Table 3.

<figure>
  <table>
    <tr><th>Purpose</th><th>ASN Range</th><th>Number of ASes</th><th>First SCION-mapped Prefix</th><th>Last SCION-mapped Prefix</th></tr>
    <tr><td>Documentation and sample code</td><td>64496-64511</td><td>16</td><td>fc00:fb:f000::/40</td><td>fc00:fb:ff00::/40</td></tr>
    <tr><td>Private Use</td><td>64512-65534</td><td>1023</td><td>fc00:fc::/40</td><td>fc00:ff:fe00::/40</td></tr>
  </table>
  <figcaption>Table 3: SCION-mapped IP prefixes derived from private BGP ASN ranges. The shown
  prefixes have an ISD of 0, replace with the correct ISD when using these prefixes.
  </figcaption>
</figure>

### Embedding the Host Address ###

Within a SCION AS host are addresses either by IPv4 or IPv6 address. When a SM-IP contains an IPv6
host address, the 64-bit Interface ID (IID) is set to `0x0000'ffff'xxxx'xxxx` where x is the full
IPv4 address. If the address format has space for a local prefix, the local prefix bits must be
zero. The reason to include `0xffff` in the IID is to avoid confusion with small
administrator-assigned IPv6 addresses such as ::1 or ::cafe that should not be mistaken for IPv4
hosts.

It is not possible to represent arbitrary IPv6 host addresses in an SM-IP. Instead, we specify that
when IPv6 is used as SCION underlay, the SM-IP itself is used as host address. The IID and AS-local
prefix may be derived from another IPv6 address the host already has. For example, if the AS uses a
global unicast prefix of length /40, with Format A SM-IPs, the last 88 bits of host addresses can be
shared between Internet and SCION addresses. If the direct use of SM-IPs is to be avoid due to
concern of assigning additional IPv6 addresses, it is also possible to employ prefix translation
(NAT66) in combination with SCION-IP translation to translate SM-IPs to a different ULA or GUA
prefix.

### Format A: 19-bit BGP ASN with 24-bit local prefix and 64-bit interface ID ###

Format A contains a 12-bit ISD, a 19-bit ASN directly representing BGP ASN 0 to 524,287
(2<sup>19</sup>-1), and space for a 24-bit AS-local prefix. The full 64-bit Interface ID is
available for SLAAC. The local prefix may be subdivided in an AS-local prefix that is part of the
global routing prefix as defined in [[RFC 4291]], and a subnet ID.

<figure>
  <table>
    <tr align="center"><td colspan=7>128-bit IPv6 address</td></tr>
    <tr align="center"><td>8 bit</td><td>12 bit</td><td>1 bit</td><td>19 bit</td><td>24 - m bit</td><td>m bit</td><td>64 bit</td></tr>
    <tr align="center"><td colspan=5>global routing prefix</td><td>subnet ID</td><td>interface ID</td></tr>
    <tr align="center"><td>0xfc</td><td>ISD</td><td>1</td><td>ASN</td><td>local prefix</td><td>subnet ID</td><td>interface ID</td></tr>
  </table>
  <figcaption>Table 4: SCION-mapped IPv6 Address Format A with IP6 host addressing</figcaption>
</figure>

<figure>
  <table>
    <tr align="center"><td colspan=8>128-bit IPv6 address</td></tr>
    <tr align="center"><td>8 bit</td><td>12 bit</td><td>1 bit</td><td>19 bit</td><td>24 - m bit</td><td>m bit</td><td>32 bit</td><td>32 bit</td></tr>
    <tr align="center"><td colspan=5>global routing prefix</td><td>subnet ID</td><td colspan=2>interface ID</td></tr>
    <tr align="center"><td>0xfc</td><td>ISD</td><td>1</td><td>ASN</td><td>0</td><td>0</td><td>0xFFFF</td><td>IPv4 address</td></tr>
  </table>
  <figcaption>Table 5: SCION-mapped IPv6 Address Format A with IP4 host addressing</figcaption>
</figure>

### Format D: 32-bit SCION ASN with 8-bit local prefix and 64-bit interface ID ###

Format D contains a 12-bit ISD, a 32-bit ASN, and an 8-bit AS-local prefix. The encoded ASN
represents public SCION ASNs from `2:0:0` to `2:ffff:ffff` with the leading 16-bit word (`0x0002`)
implicit. The full 64-bit Interface ID is available for SLAAC. The local prefix may be subdivided in
an AS-local prefix that is part of the global routing prefix as defined in [[RFC 4291]], and a
subnet ID.

<figure>
  <table>
    <tr align="center"><td colspan=7>128-bit IPv6 address</td></tr>
    <tr align="center"><td>8 bit</td><td>12 bit</td><td>4 bit</td><td>32 bit</td><td>8 - m bit</td><td>m bit</td><td>64 bit</td></tr>
    <tr align="center"><td colspan=5>global routing prefix</td><td>subnet ID</td><td>interface ID</td></tr>
    <tr align="center"><td>0xfc</td><td>ISD</td><td>0xE</td><td>ASN</td><td>local prefix</td><td>subnet ID</td><td>interface ID</td></tr>
  </table>
  <figcaption>Table 6: SCION-mapped IPv6 Address Format D with IP6 host addressing</figcaption>
</figure>

<figure>
  <table>
    <tr align="center"><td colspan=8>128-bit IPv6 address</td></tr>
    <tr align="center"><td>8 bit</td><td>12 bit</td><td>4 bit</td><td>32 bit</td><td>8 - m bit</td><td>m bit</td><td>32 bit</td><td>32 bit</td></tr>
    <tr align="center"><td colspan=5>global routing prefix</td><td>subnet ID</td><td colspan=2>interface ID</td></tr>
    <tr align="center"><td>0xfc</td><td>ISD</td><td>0xE</td><td>ASN</td><td>0</td><td>0</td><td>0xFFFF</td><td>IPv4 address</td></tr>
  </table>
  <figcaption>Table 7: SCION-mapped IPv6 Address Format D with IP4 host addressing</figcaption>
</figure>

[SCION Registry]: https://registry.scion.org/public/ases
[RFC 4193]: https://www.rfc-editor.org/rfc/rfc4193.html
[RFC 4291]: https://www.rfc-editor.org/rfc/rfc4291.html

Implementations
---------------

This repository contains generic IP-SCION translation code and the following complete translator
applications:

- [Scitra-TUN](docs/scitra-tun.md) A SCION-IP Translator for Linux hosts that enables all IPv6
  applications to communicate over a SCION network. Can be run as a daemon or with an interactive
  user interface.

Additional Resources
--------------------

- [scion2ip](tools/scion2ip/README.md) A tool that converts between SCION
  and IPv6 address to help with network configuration.
