from pathlib import Path
from datetime import datetime
from scapy_scion.layers.scion import SCIONPath, InfoField, HopField
from tests import write_packets


full = SCIONPath(
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
        HopField(cons_ingress=4, cons_egress=0, exp_time=100),
        HopField(cons_ingress=2, cons_egress=3, exp_time=100),
        HopField(cons_ingress=0, cons_egress=1, exp_time=100),
        # Segment 2
        HopField(cons_ingress=0, cons_egress=5, exp_time=20),
        HopField(cons_ingress=6, cons_egress=0, exp_time=10),
        # Segment 3
        HopField(cons_ingress=0, cons_egress=7),
        HopField(cons_ingress=8, cons_egress=9),
        HopField(cons_ingress=10, cons_egress=11),
        HopField(cons_ingress=12, cons_egress=0, exp_time=255),
    ],
)

full_rev = SCIONPath(
    curr_inf = 0,
    curr_hf = 0,
    seg0_len = 4,
    seg1_len = 2,
    seg2_len = 3,
    info_fields = [
        InfoField(flags="", segid=3,
            timestamp=datetime.fromisoformat("2025-03-25T14:00:00Z")),
        InfoField(flags="", segid=2,
            timestamp=datetime.fromisoformat("2025-03-25T13:00:00Z")),
        InfoField(flags="C", segid=1,
            timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
    ],
    hop_fields = [
        # Segment 3
        HopField(cons_ingress=12, cons_egress=0, exp_time=255),
        HopField(cons_ingress=10, cons_egress=11),
        HopField(cons_ingress=8, cons_egress=9),
        HopField(cons_ingress=0, cons_egress=7),
        # Segment 2
        HopField(cons_ingress=6, cons_egress=0, exp_time=10),
        HopField(cons_ingress=0, cons_egress=5, exp_time=20),
        # Segment 1
        HopField(cons_ingress=0, cons_egress=1, exp_time=100),
        HopField(cons_ingress=2, cons_egress=3, exp_time=100),
        HopField(cons_ingress=4, cons_egress=0, exp_time=100),
    ],
)

shortcut = SCIONPath(
    curr_inf = 1,
    curr_hf = 3,
    seg0_len = 2,
    seg1_len = 2,
    seg2_len = 0,
    info_fields = [
        InfoField(flags="", segid=1,
            timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
        InfoField(flags="C", segid=2,
            timestamp=datetime.fromisoformat("2025-03-25T13:00:00Z")),
    ],
    hop_fields = [
        # Segment 1
        HopField(cons_ingress=4, cons_egress=0),
        HopField(cons_ingress=2, cons_egress=3),
        # Segment 2
        HopField(cons_ingress=8, cons_egress=9),
        HopField(cons_ingress=10, cons_egress=0),
    ],
)

shortcut_rev = SCIONPath(
    curr_inf = 0,
    curr_hf = 0,
    seg0_len = 2,
    seg1_len = 2,
    seg2_len = 0,
    info_fields = [
        InfoField(flags="", segid=2,
            timestamp=datetime.fromisoformat("2025-03-25T13:00:00Z")),
        InfoField(flags="C", segid=1,
            timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
    ],
    hop_fields = [
        # Segment 2
        HopField(cons_ingress=10, cons_egress=0),
        HopField(cons_ingress=8, cons_egress=9),
        # Segment 1
        HopField(cons_ingress=2, cons_egress=3),
        HopField(cons_ingress=4, cons_egress=0),
    ],
)

peering = SCIONPath(
    curr_inf = 1,
    curr_hf = 5,
    seg0_len = 3,
    seg1_len = 3,
    seg2_len = 0,
    info_fields = [
        InfoField(flags="P", segid=1,
            timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
        InfoField(flags="C+P", segid=3,
            timestamp=datetime.fromisoformat("2025-03-25T13:00:00Z")),
    ],
    hop_fields = [
        # Segment 1
        HopField(cons_ingress=6, cons_egress=0),
        HopField(cons_ingress=4, cons_egress=5),
        HopField(cons_ingress=2, cons_egress=3),
        # Segment 2
        HopField(cons_ingress=7, cons_egress=8),
        HopField(cons_ingress=9, cons_egress=10),
        HopField(cons_ingress=11, cons_egress=0),
    ],
)

peering_rev = SCIONPath(
    curr_inf = 0,
    curr_hf = 0,
    seg0_len = 3,
    seg1_len = 3,
    seg2_len = 0,
    info_fields = [
        InfoField(flags="P", segid=3,
            timestamp=datetime.fromisoformat("2025-03-25T13:00:00Z")),
        InfoField(flags="C+P", segid=1,
            timestamp=datetime.fromisoformat("2025-03-25T12:00:00Z")),
    ],
    hop_fields = [
        # Segment 2
        HopField(cons_ingress=11, cons_egress=0),
        HopField(cons_ingress=9, cons_egress=10),
        HopField(cons_ingress=7, cons_egress=8),
        # Segment 1
        HopField(cons_ingress=2, cons_egress=3),
        HopField(cons_ingress=4, cons_egress=5),
        HopField(cons_ingress=6, cons_egress=0),
    ],
)

paths = [full, full_rev, shortcut, shortcut_rev, peering, peering_rev]
write_packets(paths, Path(__file__).with_suffix(".bin"))
