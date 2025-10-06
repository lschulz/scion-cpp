from pathlib import Path
from datetime import datetime
from scapy_scion.layers.scion import UDP, SCION, SCIONPath, InfoField, HopField
from tests import write_packets


raw_path = SCIONPath(
    curr_inf=0,
    curr_hf=0,
    seg0_len=3, seg1_len=0, seg2_len=0,
    info_fields=[
        InfoField(flags="C", segid=0xa9b8, timestamp=datetime.fromtimestamp(1704063600))
    ],
    hop_fields=[
        HopField(exp_time=0xc1, cons_ingress=0, cons_egress=2, mac=0x7bd910c68949),
        HopField(exp_time=0xd0, cons_ingress=5, cons_egress=4, mac=0xbd20087f1ebb),
        HopField(exp_time=0x27, cons_ingress=3, cons_egress=0, mac=0x5fc3be952300)
    ]
)

quote1 = SCION(
    plen = 65500,
    dst_isd = 1,
    dst_asn = "ff00:0:1",
    src_isd = 2,
    src_asn = "ff00:0:2",
    dst_host = "::1",
    src_host = "fd00::2",
    path = raw_path
) / UDP(sport=32000, dport=32001)

quote2 = SCION(
    plen = 8000,
    dst_isd = 1,
    dst_asn = "ff00:0:1",
    src_isd = 2,
    src_asn = "ff00:0:2",
    dst_host = "::1",
    src_host = "fd00::2",
    path = raw_path
) / UDP(sport=32000, dport=32001)

write_packets([raw_path, quote1, quote2], Path(__file__).with_suffix(".bin"))
