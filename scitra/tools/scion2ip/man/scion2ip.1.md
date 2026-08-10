% scion2ip(1) Version 0.1.0 | Scitra Manual

## NAME ##

scion2ip - converts between SCION addresses and SCION-mapped IPv6 addresses

## SYNOPSIS ##

| **scion2ip** \[**-d**\] \[**-l**|**--subnet-bits** subnet_bits\] \[**-p**|**--prefix** prefix\]
    \[**-s**|**--subnet** subnet\]  \[scion_address\]
| **scion2ip** \[**-dv**\]  \[**-l**|**--subnet-bits** subnet_bits\] \[ip_address\]

## DESCRIPTION ##

scion2ip attempts to convert SCION addresses given on the command line to SCION-mapped IPv6
addresses and SCION-mapped IPv6 addresses to their full SCION equivalent.

SCION addresses must be given in the format `ISD-ASN,IP`. The format of SCION-mapped IPv6 addresses
changes depending on the value of `ASN`. If the ASN is BGP-derived with a value smaller than 524,288
(2^19), the SCION-mapped IPv6 address has space for a 24-bit AS-local routing prefix. If the ASN is
a public SCION address between `2:0:0` and `2:ffff:fff` (inclusive), the local prefix has a length
of 8 bits. Other ASNs cannot be converted. In all cases, the ISD must be smaller than 4096 (2^12).
The IP address part must be an IPv4 address, an IPv4-mapped IPv6 address, an IPv6 host address
without a routing prefix (just the 24/8-bit local prefix and interface ID), or a SCION-mapped IPv6
address whose prefix encodes the same ISD and ASN as given in the SCION part of the address. When
converting from SCION to IPv6, the local routing prefix can also be set with the `-p,--prefix`
option. Part of the local prefix may be interpreted as subnet ID. The length of the subnet ID is set
with the `-l,--subnet-bits` option. The subnet itself is set with `-s,--subnet`. The default subnet
length is 8 bits.

SCION-mapped IPv6 addresses are given in the usual IPv6 address format. By default scion2ip outputs
the SCION address in the format `ISD-ASN,IP`. If `IP` is an IPv6 address and `-v` is specified, the
local routing prefix and subnet are printed on the same line after the SCION address.

## OPTIONS ##

`-h, ---help` Show command syntax.

`-l, --subnet-bits` _subnet_bits_ Length of the subnet address for SCION-IPv6 host addresses.
    The default is 8.

`-p, --prefix` _prefix_ Sets the IPv6 routing prefix withing the AS. Ignored if the host part of
    the address is IPv4.

`-s, --subnet` _subnet_ Sets the subnet routing prefix. Ignored if the host part of the address is
    IPv4.

`-d, --describe` Instead of printing the translated address, describe the format of SCION-mapped
    IPv6 this address is an example of.

`-v, --verbose` Print extracted local prefix and subnet in addition to translated address when
    converting from SCION-mapped IPv6 to SCION.

`-V, --version` Display program version and exit.

## EXAMPLES ##

```bash
$ scion2ip 1-64496,10.0.0.1
fc00:10fb:f000::ffff:10.0.0.1

$ scion2ip 1-64496,::1
fc00:10fb:f000::1

$ scion2ip 1-64496,::1 -p 0xffff -s 1
fc00:10fb:f0ff:ff01::1

$ scion2ip 1-2:0:0,::1
fc00:1e00::1

$ scion2ip fc00:10fb:f000::ffff:10.0.0.1
1-64496,10.0.0.1

$ scion2ip fc00:10fb:f000::1
1-64496,fc00:10fb:f000::1

$ scion2ip fc00:10fb:f0ff:ff01::1
1-64496,fc00:10fb:f0ff:ff01::1

$ scion2ip fc00:10fb:f0ff:ff01::1 -v
1-64496,fc00:10fb:f0ff:ff01::1 0xffff 0x1

$ scion2ip fc00:1e00::1 -d
32-bit SCION ASN between 2:0:0 and 2:ffff:ffff with 8-bit local prefix and 64-bit interface ID
```

## AUTHOR ##

Lars-Christian Schulz <lschulz@ovgu.de>

## SEE ALSO ##

scitra-tun(8)
