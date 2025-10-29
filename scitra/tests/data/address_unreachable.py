from pathlib import Path
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, IPerror6, UDP
from tests import write_packets


payload = b"TEST"

ip1 = IPv6(
    tc = 32,
    fl = 0xddd6b,
    hlim = 64,
    src = "fc00:10fb:f000::ffff:a00:1",
    dst = "fd00::1"
) / UDP(
    sport = 32766,
    dport = 32767
) / payload

unreachable = IPv6(
    tc = 32,
    fl = 0xddd6b,
    hlim = 64,
    src = "fc00::1",
    dst = "fc00:10fb:f000::ffff:a00:1"
) / ICMPv6DestUnreach(
    code = 3 # address unreachable
) / bytes(ip1)

write_packets([ip1, unreachable], Path(__file__).with_suffix(".bin"))
