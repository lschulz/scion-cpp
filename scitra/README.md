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

Implementations
---------------

This repository contains generic IP-SCION translation code and the following complete translator
applications:

- [Scitra-TUN](docs/scitra-tun.md) A SCION-IP Translator for Linux hosts that enables all IPv6
  applications ini the same host to communicate over a SCION network.Can be run as a daemon or with
  an interactive user interface.

Additional Resources
--------------------

- [SCION-mapped IPv6 Address Converter](tools/scion2ip/README.md) A tool that converts between SCION
  and IPv6 address to help with network configuration.
