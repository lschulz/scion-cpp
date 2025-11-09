from pathlib import Path
from datetime import datetime
from scapy.layers.inet6 import IPv6
from scapy_scion.layers.scion import UDP, SCION, SCIONPath, InfoField, HopField
from tests import write_packets


payload = b"TEST"

path = SCIONPath(
    curr_inf = 2,
    curr_hf = 8,
    seg0_len = 3,
    seg1_len = 2,
    seg2_len = 4,
    info_fields = [
        InfoField(flags="", segid=1,
            timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
        InfoField(flags="C", segid=2,
            timestamp=datetime.fromisoformat("2025-03-25T13:00:00Z")),
        InfoField(flags="C", segid=3,
            timestamp=datetime.fromisoformat("2025-03-25T14:00:00Z")),
    ],
    hop_fields = [
        # Segment 1
        HopField(cons_ingress=4, cons_egress=0),
        HopField(cons_ingress=2, cons_egress=3),
        HopField(cons_ingress=0, cons_egress=1),
        # Segment 2
        HopField(cons_ingress=0, cons_egress=5),
        HopField(cons_ingress=6, cons_egress=0),
        # Segment 3
        HopField(cons_ingress=0, cons_egress=7),
        HopField(cons_ingress=8, cons_egress=9),
        HopField(cons_ingress=10, cons_egress=11),
        HopField(cons_ingress=12, cons_egress=0),
    ]
)

ip = IPv6(
    tc = 32,
    fl = 0x71d6c,
    hlim = 64,
    src = "fc00:10fb:f000::1",
    dst = "fc00:20fb:f100::2"
) / UDP(
    sport = 32766,
    dport = 32767
) / payload

scion = IPv6(
    tc = 32,
    fl = 0x71d6c,
    hlim = 64,
    src = "fc00:10fb:f000::1",
    dst = "::1"
) / UDP(
    sport = 32766,
    dport = 31002
) / SCION(
    qos = 32,
    fl = 0x71d6d,
    dst_isd = 2,
    dst_asn = "64497",
    src_isd = 1,
    src_asn = "64496",
    dst_host = "fc00:20fb:f100::2",
    src_host = "fc00:10fb:f000::1",
    path = path
) / UDP(
    sport = 32766,
    dport = 32767
) / payload

write_packets([ip, scion], Path(__file__).with_suffix(".bin"))
