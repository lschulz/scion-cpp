from pathlib import Path
from datetime import datetime
from scapy.layers.inet import TCP
from scapy_scion.layers.scion import SCION, SCIONPath, InfoField, HopField
from tests import write_packets


payload = b"TEST"

path = SCIONPath(
    curr_inf = 1,
    curr_hf = 3,
    seg0_len = 2,
    seg1_len = 2,
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
        HopField(cons_ingress=0, cons_egress=1),
        # Segment 2
        HopField(cons_ingress=0, cons_egress=5),
        HopField(cons_ingress=6, cons_egress=0),
    ]
)

input = SCION(
    qos = 32,
    fl = 0x86c8b,
    dst_isd = 2,
    dst_asn = "64497",
    src_isd = 1,
    src_asn = "64496",
    dst_host = "10.0.0.2",
    src_host = "10.0.0.1",
    path = path
) / TCP(
    sport = 32766,
    dport = 32767
) / payload

output = bytes(input)[:-len(payload)]

write_packets([input, output], Path(__file__).with_suffix(".bin"))
