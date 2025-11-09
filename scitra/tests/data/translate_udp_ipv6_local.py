from pathlib import Path
from scapy.layers.inet6 import IPv6
from scapy_scion.layers.scion import UDP, SCION, EmptyPath
from tests import write_packets


payload = b"TEST"

path = EmptyPath()

ip = IPv6(
    tc = 32,
    fl = 0xc63bd,
    hlim = 64,
    src = "fc00:10fb:f000::1",
    dst = "fc00:10fb:f000::2"
) / UDP(
    sport = 32766,
    dport = 32767
) / payload

scion = IPv6(
    tc = 32,
    fl = 0xc63bd,
    hlim = 64,
    src = "fc00:10fb:f000::1",
    dst = "fc00:10fb:f000::2"
) / UDP(
    sport = 32766,
    dport = 32767
) / SCION(
    qos = 32,
    fl = 0xc63bd,
    dst_isd = 1,
    dst_asn = "64496",
    src_isd = 1,
    src_asn = "64496",
    dst_host = "fc00:10fb:f000::2",
    src_host = "fc00:10fb:f000::1",
    path = path
) / UDP(
    sport = 32766,
    dport = 32767
) / payload

write_packets([ip, scion], Path(__file__).with_suffix(".bin"))
