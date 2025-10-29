from pathlib import Path
from scapy.layers.inet6 import IPv6, ICMPv6DestUnreach, IPerror6, UDP
from tests import write_packets


payload = 1400 * b"X"

ip = IPv6(
    tc = 32,
    fl = 0xddd6b,
    hlim = 64,
    src = "fc00:10fb:f000::ffff:a00:1",
    dst = "fc00:20fb:f100::ffff:a00:2"
) / UDP(
    sport = 32766,
    dport = 32767
) / payload

response = IPv6(
    tc = 32,
    fl = 0xddd6b,
    hlim = 64,
    src = "fc00::1",
    dst = "fc00:10fb:f000::ffff:a00:1"
) / ICMPv6DestUnreach(
    code = 0 # no route to destination
) / bytes(ip)[:1232]

write_packets([ip, response], Path(__file__).with_suffix(".bin"))
