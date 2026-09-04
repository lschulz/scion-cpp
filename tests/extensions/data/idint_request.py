from pathlib import Path
from scapy_scion.layers.scion import HopByHopExt
from scapy_scion.layers.idint import IdIntOption, IdIntEntry
from tests import write_packets


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
        stack_len=96,
        stack = [
            IdIntEntry(flags="source", hop=0, mac=b"\xd8\x19\xc9\x98", mask="node_id",
                node_id=2, md1=(3).to_bytes(6, 'big'), md2=(4).to_bytes(2, 'big')),
        ]
    )
])

write_packets(ext, Path(__file__).with_suffix(".bin"))
