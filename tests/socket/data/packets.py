from pathlib import Path
from datetime import datetime
from scapy_scion.layers.scion import (
    UDP, SCION, SCIONPath, InfoField, HopField, HopByHopExt
)
from scapy_scion.layers.idint import IdIntOption, IdIntEntry
from scapy_scion.layers.scmp import SCMP, ScmpEchoRequest
from tests import write_packets


path = SCIONPath(
    curr_inf = 0,
    curr_hf = 0,
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
    ],
)

scion = SCION(
    qos = 64,
    dst_isd = 2,
    dst_asn = "ff00:0:2",
    src_isd = 1,
    src_asn = "ff00:0:1",
    dst_host = "fd00::1",
    src_host = "10.0.0.1",
    path = path,
)

ext = HopByHopExt(options=[
    IdIntOption(
        flags="discard",
        aggregation="as",
        verifier="destination",
        inst_flags="node_id",
        af1="last",
        af2="last",
        inst1="ingress_tstamp",
        inst2="device_type_role",
        source_ts=1000,
        source_port=10,
        stack_len = 16,
        stack = [
            IdIntEntry(flags="source", hop=0, mac=4*b"\xff", mask="node_id",
                node_id=2, md1=(3).to_bytes(4, 'big'), md2=(4).to_bytes(2, 'big')),
        ]
    )
])

udp = UDP(sport=3000, dport=8000)
scmp = SCMP(message=ScmpEchoRequest(id=1, seq=100))

payload = b"\x01\x02\x03\x04\x05\x06\x07\x08"
payload2 = b"\xff\xff\xff\xff\xff\xff\xff\xff\x07\x06\x05\x04\x03\x02\x01\x00"

pkts = []

# UDP
scion.fl = 0x054b20
pkts.append(bytes(scion / udp / payload))

# UDP with different payload
scion.fl = 0x054b20
pkts.append(bytes(scion / udp / payload2))

# SCMP
scion.fl = 0x017124
pkts.append(bytes(scion / scmp / payload))

# SCMP no payload
scion.fl = 0x054b20
pkts.append(bytes(scion / scmp))

# UDP with ID-INT
scion.fl = 0x054b20
pkts.append(bytes(scion / ext / udp / payload))

# UDP with incorrect checksum
udp.chksum = 0
pkts.append(bytes(scion / udp / payload))

write_packets(pkts, Path(__file__).with_suffix(".bin"))
