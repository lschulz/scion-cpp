from pathlib import Path
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy_scion.layers.scion import UDP, SCION, EmptyPath
from tests import write_packets


payload = b"TEST"

path = EmptyPath()

ip = IPv6(
    tc = 32,
    fl = 0x9646,
    hlim = 64,
    src = "fc00:10fb:f000::ffff:a00:1",
    dst = "fc00:10fb:f000::ffff:a00:2"
) / UDP(
    sport = 32766,
    dport = 32767
) / payload

scion = IP(
    tos = 32,
    ttl = 64,
    id = 0,
    flags = "DF",
    frag = 0,
    src = "10.0.0.1",
    dst = "10.0.0.2"
) / UDP(
    sport = 32766,
    dport = 32767
) / SCION(
    qos = 32,
    fl = 0x86c8a,
    dst_isd = 1,
    dst_asn = "64496",
    src_isd = 1,
    src_asn = "64496",
    dst_host = "10.0.0.2",
    src_host = "10.0.0.1",
    path = path
) / UDP(
    sport = 32766,
    dport = 32767
) / payload

write_packets([ip, scion], Path(__file__).with_suffix(".bin"))
