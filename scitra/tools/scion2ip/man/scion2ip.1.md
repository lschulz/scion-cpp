% scion2ip(1) Version 0.0.1 | Scitra Manual

## NAME ##

scion2ip - converts between SCION addresses and SCION-mapped IPv6 addresses

## SYNOPSIS ##

| **scion2ip** \[**-l**|**--subnet-bits** subnet_bits\] \[**-p**|**--prefix** prefix\]
    \[**-s**|**--subnet** subnet\]  \[scion_address\]
| **scion2ip** \[**-l**|**--subnet-bits** subnet_bits\] \[**-v**|**--verbose**\] \[ip_address\]

## DESCRIPTION ##

scion2ip attempts to convert SCION addresses given on the command line to SCION-mapped IPv6
addresses and SCION-mapped IPv6 addresses to their full SCION equivalent.

SCION addresses must be given in the format `ISD-ASN,IP`. Conversion is only possible if `ISD < 4096
(2^12)`. The ASN must be BGP-compatible with `ASN < 524288 (2^19)` or a SCION ASN between `2:0:0` to
`2:7:fff` (inclusive). The IP address must be an IPv4 address, an IPv4-mapped IPv6 address, an IPv6
host address without a SCION routing prefix (i.e. the first 40 bits of the address are zero), or a
SCION-mapped IPv6 address whose prefix encodes the same ISD and ASN as given in the SCION part of
the address. SCION-mapped IPv6 addresses may contain an AS-local routing prefix and a local subnet.
Both can be set or replaced during conversion using the `-p` and `-s` option, respectively. `-p` and
`-s` have no effect when converting IPv4 addresses.

SCION-mapped IPv6 addresses are given in the usual IPv6 address format. By default scion2ip outputs
the SCION address in the format `ISD-ASN,IP`. If `IP` is an IPv6 address and `-v` is specified, the
local routing prefix and subnet are printed on the same line after the SCION address.

## OPTIONS ##

`-h, ---help` Show command syntax.

`-l, --subnet-bits` _subnet_bits_ Length of the subnet address for SCION-IPv6 host addresses.
    Must be in [0, 24]. The default is 8.

`-p, --prefix` _prefix_ Sets the IPv6 routing prefix withing the AS. Ignored if the host part of
    the address is IPv4.

`-s, --subnet` _subnet_ Sets the subnet routing prefix. Ignored if the host part of the address is
    IPv4.

`-v, --verbose` Print extracted local prefix and subnet in addition to translated address when
    converting from SCION-mapped IPv6 to SCION.

`-V, --version` Display program version and exit.

## EXAMPLES ##

```bash
$ scion2ip 1-64512,10.0.0.1
fc00:10fc::ffff:10.0.0.1

$ scion2ip 1-64512,::1
fc00:10fc::1

$ scion2ip 1-2:0:0,::1 -p 0xff -s 1
fc00:1800:0:ff01::1

$ scion2ip fc00:10fc::ffff:a00:1
1-64512,10.0.0.1

$ scion2ip fc00:10fc::1
1-64512,fc00:10fc::1

$ scion2ip fc00:1800:0:ff01::1
1-2:0:0,fc00:1800:0:ff01::1

$ scion2ip fc00:1800:0:ff01::1 -v
1-2:0:0,fc00:1800:0:ff01::1 0xff 0x1
```

## AUTHOR ##

Lars-Christian Schulz <lschulz@ovgu.de>

## SEE ALSO ##

scitra-tun(8)
