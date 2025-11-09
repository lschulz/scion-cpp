SCION2IP
========

Converts between SCION and SCION-mapped IPv6 addresses.

SCION addresses are given as whitespace separated tuple of ISD-ASN, local prefix, subnet, and
interface address. Local prefix, subnet, and IPv6 interface identifiers are in hexadecimal. IPv4
interface must be given in dotted decimal form with prefix and subnet set to zero.

Examples:
```bash
$ ./scion2ip 1-64512 0 0 1
fc00:10fc::1
$ ./scion2ip 1-2:0:0 0 0 10.0.0.1
fc00:1800::ffff:a00:1
$ ./ip2scion fc00:10fc:200::1
1-64514 0 0 1
$ ./ip2scion fc00:10fc::ffff:a80:1
1-64512 0 0 10.128.0.1
```

### Mapping of SCION addresses to IPv6 addresses
SCION addresses are converted to IPv6 by truncating the ISD to 12 bit and the ASN to 20 bit. ASNs 0
to 2<sup>19</sup>-1 are represented directly. ASNs 2:0:0 to 2:7:ffff are encoded as `(1 << 19) |
(asn & 0x7ffff)`. Thus the most significant bit of the encoded ASN is used to distinguish
BGP-compatible and SCION-only ASNs. All SCION-mapped IPv6 addresses have a common 8 bit prefix which
is currently set to `fc00::/8`.

SCION IPv4 host addresses are represented by storing the IPv4 address in the lower half of the
interface ID and setting the upper half to `0x0000ffff`. The local routing prefix and subnet ID must
also be zero.

#### SCION-IPv6 in IPv6
<table>
<tr align="center"><td colspan=6>128-bit IPv6 address</td></tr>
<tr align="center"><td>8 bit</td><td>12 bit</td><td>20 bit</td><td>24 - m bit</td><td>m bit</td><td>64 bit</td></tr>
<tr align="center"><td colspan=4>global routing prefix</td><td>subnet ID</td><td>interface ID</td></tr>
<tr align="center"><td>0xfc</td><td>ISD</td><td>ASN</td><td>local prefix</td><td>subnet ID</td><td>interface ID</td></tr>
</table>

#### SCION-IPv4 in IPv6
<table>
<tr align="center"><td colspan=7>128-bit IPv6 address</td></tr>
<tr align="center"><td>8 bit</td><td>12 bit</td><td>20 bit</td><td>24 - m bit</td><td>m bit</td><td>32 bit</td><td>32 bit</td></tr>
<tr align="center"><td colspan=4>global routing prefix</td><td>subnet ID</td><td colspan=2>interface ID</td></tr>
<tr align="center"><td>0xfc</td><td>ISD</td><td>ASN</td><td>0</td><td>0</td><td>0xffff</td><td>IPv4 address</td></tr>
</table>
