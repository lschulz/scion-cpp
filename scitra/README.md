Scitra: The SCION-IP Translator
===============================

Scitra-TUN
----------
A SCION-IP Translator for Linux. Creates a TUN device and sets up a route to
capture traffic addressed to the SCION-mapped IPv6 prefix fc00::/8. Communicates
with border routers and other SCION hosts via UDP socket that are dynamically
created and destroyed.

Scitra-Tun requires `CAP_NET_ADMIN` to modify network interfaces. Capabilities
must be assigned manually by root after building the binary. e.g.
```bash
sudo setcap CAP_NET_ADMIN=ep build/scitra/Release/scitra-tun
```
